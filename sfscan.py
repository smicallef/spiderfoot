# -*- coding: utf-8 -*-
# -----------------------------------------------------------------
# Name:         sfscan
# Purpose:      Scanning control functionality
#
# Author:       Steve Micallef <steve@binarypool.com>
#
# Created:      11/03/2013
# Copyright:    (c) Steve Micallef 2013
# License:      MIT
# -----------------------------------------------------------------
import socket
import time
import queue
from time import sleep
from copy import deepcopy
from contextlib import suppress
from collections import OrderedDict

import dns.resolver

from sflib import SpiderFoot
from spiderfoot import SpiderFootDb, SpiderFootEvent, SpiderFootPlugin, SpiderFootTarget, SpiderFootHelpers, SpiderFootThreadPool, SpiderFootCorrelator, logger


def startSpiderFootScanner(loggingQueue, *args, **kwargs):
    logger.logWorkerSetup(loggingQueue)
    return SpiderFootScanner(*args, **kwargs)


class SpiderFootScanner():
    """SpiderFootScanner object.

    Attributes:
        scanId (str): unique ID of the scan
        status (str): status of the scan
    """

    __scanId = None
    __status = None
    __config = None
    __sf = None
    __dbh = None
    __targetValue = None
    __targetType = None
    __moduleList = list()
    __target = None
    __moduleInstances = dict()
    __modconfig = dict()
    __scanName = None

    def __init__(self, scanName: str, scanId: str, targetValue: str, targetType: str, moduleList: list, globalOpts: dict, start: bool = True) -> None:
        """Initialize SpiderFootScanner object.

        Args:
            scanName (str): name of the scan
            scanId (str): unique ID of the scan
            targetValue (str): scan target
            targetType (str): scan target type
            moduleList (list): list of modules to run
            globalOpts (dict): scan options
            start (bool): start the scan immediately

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid

        Todo:
             Eventually change this to be able to control multiple scan instances
        """
        if not isinstance(globalOpts, dict):
            raise TypeError(f"globalOpts is {type(globalOpts)}; expected dict()")
        if not globalOpts:
            raise ValueError("globalOpts is empty")

        self.__config = deepcopy(globalOpts)
        self.__dbh = SpiderFootDb(self.__config)

        if not isinstance(scanName, str):
            raise TypeError(f"scanName is {type(scanName)}; expected str()")
        if not scanName:
            raise ValueError("scanName value is blank")

        self.__scanName = scanName

        if not isinstance(scanId, str):
            raise TypeError(f"scanId is {type(scanId)}; expected str()")
        if not scanId:
            raise ValueError("scanId value is blank")

        if not isinstance(targetValue, str):
            raise TypeError(f"targetValue is {type(targetValue)}; expected str()")
        if not targetValue:
            raise ValueError("targetValue value is blank")

        self.__targetValue = targetValue

        if not isinstance(targetType, str):
            raise TypeError(f"targetType is {type(targetType)}; expected str()")
        if not targetType:
            raise ValueError("targetType value is blank")

        self.__targetType = targetType

        if not isinstance(moduleList, list):
            raise TypeError(f"moduleList is {type(moduleList)}; expected list()")
        if not moduleList:
            raise ValueError("moduleList is empty")

        self.__moduleList = moduleList
        self.__sf = SpiderFoot(self.__config)
        self.__sf.dbh = self.__dbh

        # Create a unique ID for this scan in the back-end DB.
        if scanId:
            self.__scanId = scanId
        else:
            self.__scanId = SpiderFootHelpers.genScanInstanceId()

        self.__sf.scanId = self.__scanId
        self.__dbh.scanInstanceCreate(self.__scanId, self.__scanName, self.__targetValue)

        # Create our target
        try:
            self.__target = SpiderFootTarget(self.__targetValue, self.__targetType)
        except (TypeError, ValueError) as e:
            self.__sf.status(f"Scan [{self.__scanId}] failed: {e}")
            self.__setStatus("ERROR-FAILED", None, time.time() * 1000)
            raise ValueError(f"Invalid target: {e}") from None

        # Save the config current set for this scan
        self.__config['_modulesenabled'] = self.__moduleList
        self.__dbh.scanConfigSet(self.__scanId, self.__sf.configSerialize(deepcopy(self.__config)))

        # Process global options that point to other places for data

        # If a proxy server was specified, set it up
        proxy_type = self.__config.get('_socks1type')
        if proxy_type:
            # TODO: allow DNS lookup to be configurable when using a proxy
            # - proxy DNS lookup: socks5h:// and socks4a://
            # - local DNS lookup: socks5:// and socks4://
            if proxy_type == '4':
                proxy_proto = 'socks4://'
            elif proxy_type == '5':
                proxy_proto = 'socks5://'
            elif proxy_type == 'HTTP':
                proxy_proto = 'http://'
            elif proxy_type == 'TOR':
                proxy_proto = 'socks5h://'
            else:
                self.__sf.status(f"Scan [{self.__scanId}] failed: Invalid proxy type: {proxy_type}")
                self.__setStatus("ERROR-FAILED", None, time.time() * 1000)
                raise ValueError(f"Invalid proxy type: {proxy_type}")

            proxy_host = self.__config.get('_socks2addr', '')

            if not proxy_host:
                self.__sf.status(f"Scan [{self.__scanId}] failed: Proxy type is set ({proxy_type}) but proxy address value is blank")
                self.__setStatus("ERROR-FAILED", None, time.time() * 1000)
                raise ValueError(f"Proxy type is set ({proxy_type}) but proxy address value is blank")

            proxy_port = int(self.__config.get('_socks3port') or 0)

            if not proxy_port:
                if proxy_type in ['4', '5']:
                    proxy_port = 1080
                elif proxy_type.upper() == 'HTTP':
                    proxy_port = 8080
                elif proxy_type.upper() == 'TOR':
                    proxy_port = 9050

            proxy_username = self.__config.get('_socks4user', '')
            proxy_password = self.__config.get('_socks5pwd', '')

            if proxy_username or proxy_password:
                proxy_auth = f"{proxy_username}:{proxy_password}"
                proxy = f"{proxy_proto}{proxy_auth}@{proxy_host}:{proxy_port}"
            else:
                proxy = f"{proxy_proto}{proxy_host}:{proxy_port}"

            self.__sf.debug(f"Using proxy: {proxy}")
            self.__sf.socksProxy = proxy
        else:
            self.__sf.socksProxy = None

        # Override the default DNS server
        if self.__config['_dnsserver']:
            res = dns.resolver.Resolver()
            res.nameservers = [self.__config['_dnsserver']]
            dns.resolver.override_system_resolver(res)
        else:
            dns.resolver.restore_system_resolver()

        # Set the user agent
        self.__config['_useragent'] = self.__sf.optValueToData(self.__config['_useragent'])

        # Set up the Internet TLD list.
        # If the cached does not exist or has expired, reload it from scratch.
        tld_data = self.__sf.cacheGet("internet_tlds", self.__config['_internettlds_cache'])
        if tld_data is None:
            tld_data = self.__sf.optValueToData(self.__config['_internettlds'])
            if tld_data is None:
                self.__sf.status(f"Scan [{self.__scanId}] failed: Could not update TLD list")
                self.__setStatus("ERROR-FAILED", None, time.time() * 1000)
                raise ValueError("Could not update TLD list")
            self.__sf.cachePut("internet_tlds", tld_data)

        self.__config['_internettlds'] = tld_data.splitlines()

        self.__setStatus("INITIALIZING", time.time() * 1000, None)

        self.__sharedThreadPool = SpiderFootThreadPool(threads=self.__config.get("_maxthreads", 3), name='sharedThreadPool')

        # Used when module threading is enabled
        self.eventQueue = None

        if start:
            self.__startScan()

    @property
    def scanId(self) -> str:
        return self.__scanId

    @property
    def status(self) -> str:
        return self.__status

    def __setStatus(self, status: str, started: float = None, ended: float = None) -> None:
        """Set the status of the currently running scan (if any).

        Args:
            status (str): scan status
            started (float): timestamp at start of scan
            ended (float): timestamp at end of scan

        Raises:
            TypeError: arg type was invalid
            ValueError: arg value was invalid
        """
        if not isinstance(status, str):
            raise TypeError(f"status is {type(status)}; expected str()")

        if status not in [
            "INITIALIZING",
            "STARTING",
            "STARTED",
            "RUNNING",
            "ABORT-REQUESTED",
            "ABORTED",
            "ABORTING",
            "FINISHED",
            "ERROR-FAILED"
        ]:
            raise ValueError(f"Invalid scan status {status}")

        self.__status = status
        self.__dbh.scanInstanceSet(self.__scanId, started, ended, status)

    def __startScan(self) -> None:
        """Start running a scan.

        Raises:
            AssertionError: Never actually raised.
        """
        failed = True

        try:
            self.__setStatus("STARTING", time.time() * 1000, None)
            self.__sf.status(f"Scan [{self.__scanId}] for '{self.__target.targetValue}' initiated.")

            self.eventQueue = queue.Queue()

            self.__sharedThreadPool.start()

            # moduleList = list of modules the user wants to run
            self.__sf.debug(f"Loading {len(self.__moduleList)} modules ...")
            for modName in self.__moduleList:
                if not modName:
                    continue

                # Module may have been renamed or removed
                if modName not in self.__config['__modules__']:
                    self.__sf.error(f"Failed to load module: {modName}")
                    continue

                try:
                    module = __import__('modules.' + modName, globals(), locals(), [modName])
                except ImportError:
                    self.__sf.error(f"Failed to load module: {modName}")
                    continue

                try:
                    mod = getattr(module, modName)()
                    mod.__name__ = modName
                except Exception:
                    self.__sf.error(f"Module {modName} initialization failed", exc_info=True)
                    continue

                # Set up the module options, scan ID, database handle and listeners
                try:
                    # Configuration is a combined global config with module-specific options
                    self.__modconfig[modName] = deepcopy(self.__config['__modules__'][modName]['opts'])
                    for opt in list(self.__config.keys()):
                        self.__modconfig[modName][opt] = deepcopy(self.__config[opt])

                    # clear any listener relationships from the past
                    mod.clearListeners()
                    mod.setScanId(self.__scanId)
                    mod.setSharedThreadPool(self.__sharedThreadPool)
                    mod.setDbh(self.__dbh)
                    mod.setup(self.__sf, self.__modconfig[modName])
                except Exception:
                    self.__sf.error(f"Module {modName} initialization failed", exc_info=True)
                    mod.errorState = True
                    continue

                # Override the module's local socket module to be the SOCKS one.
                if self.__config['_socks1type'] != '':
                    try:
                        mod._updateSocket(socket)
                    except Exception as e:
                        self.__sf.error(f"Module {modName} socket setup failed: {e}")
                        continue

                # Set up event output filters if requested
                if self.__config['__outputfilter']:
                    try:
                        mod.setOutputFilter(self.__config['__outputfilter'])
                    except Exception as e:
                        self.__sf.error(f"Module {modName} output filter setup failed: {e}")
                        continue

                # Give modules a chance to 'enrich' the original target with aliases of that target.
                try:
                    newTarget = mod.enrichTarget(self.__target)
                    if newTarget is not None:
                        self.__target = newTarget
                except Exception as e:
                    self.__sf.error(f"Module {modName} target enrichment failed: {e}")
                    continue

                # Register the target with the module
                try:
                    mod.setTarget(self.__target)
                except Exception as e:
                    self.__sf.error(f"Module {modName} failed to set target '{self.__target}': {e}")
                    continue

                # Set up the outgoing event queue
                try:
                    mod.outgoingEventQueue = self.eventQueue
                    mod.incomingEventQueue = queue.Queue()
                except Exception as e:
                    self.__sf.error(f"Module {modName} event queue setup failed: {e}")
                    continue

                self.__moduleInstances[modName] = mod
                self.__sf.status(f"{modName} module loaded.")

            self.__sf.debug(f"Scan [{self.__scanId}] loaded {len(self.__moduleInstances)} modules.")

            if not self.__moduleInstances:
                self.__setStatus("ERROR-FAILED", None, time.time() * 1000)
                self.__dbh.close()
                return

            # sort modules by priority
            self.__moduleInstances = OrderedDict(sorted(self.__moduleInstances.items(), key=lambda m: m[-1]._priority))

            # Now we are ready to roll..
            self.__setStatus("RUNNING")

            # Create a pseudo module for the root event to originate from
            psMod = SpiderFootPlugin()
            psMod.__name__ = "SpiderFoot UI"
            psMod.setTarget(self.__target)
            psMod.setDbh(self.__dbh)
            psMod.clearListeners()
            psMod.outgoingEventQueue = self.eventQueue
            psMod.incomingEventQueue = queue.Queue()

            # Create the "ROOT" event which un-triggered modules will link events to
            rootEvent = SpiderFootEvent("ROOT", self.__targetValue, "", None)
            psMod.notifyListeners(rootEvent)
            firstEvent = SpiderFootEvent(self.__targetType, self.__targetValue,
                                         "SpiderFoot UI", rootEvent)
            psMod.notifyListeners(firstEvent)

            # Special case.. check if an INTERNET_NAME is also a domain
            if self.__targetType == 'INTERNET_NAME':
                if self.__sf.isDomain(self.__targetValue, self.__config['_internettlds']):
                    firstEvent = SpiderFootEvent('DOMAIN_NAME', self.__targetValue,
                                                 "SpiderFoot UI", rootEvent)
                    psMod.notifyListeners(firstEvent)

            # If in interactive mode, loop through this shared global variable
            # waiting for inputs, and process them until my status is set to
            # FINISHED.

            # Check in case the user requested to stop the scan between modules
            # initializing
            scanstatus = self.__dbh.scanInstanceGet(self.__scanId)
            if scanstatus and scanstatus[5] == "ABORT-REQUESTED":
                raise AssertionError("ABORT-REQUESTED")

            # start threads
            self.waitForThreads()
            failed = False

        except (KeyboardInterrupt, AssertionError):
            self.__sf.status(f"Scan [{self.__scanId}] aborted.")
            self.__setStatus("ABORTED", None, time.time() * 1000)

        except BaseException as e:
            self.__sf.error(
                f"Unhandled exception ({e.__class__.__name__}) encountered during scan. Please report this as a bug",
                exc_info=True
            )
            self.__sf.status(f"Scan [{self.__scanId}] failed: {e}")
            self.__setStatus("ERROR-FAILED", None, time.time() * 1000)

        finally:
            if not failed:
                self.__setStatus("FINISHED", None, time.time() * 1000)
                self.runCorrelations()
                self.__sf.status(f"Scan [{self.__scanId}] completed.")
            self.__dbh.close()

    def runCorrelations(self) -> None:
        """Run correlation rules."""

        self.__sf.status(f"Running {len(self.__config['__correlationrules__'])} correlation rules on scan {self.__scanId}.")
        ruleset = dict()
        for rule in self.__config['__correlationrules__']:
            ruleset[rule['id']] = rule['rawYaml']
        corr = SpiderFootCorrelator(self.__dbh, ruleset, self.__scanId)
        corr.run_correlations()

    def waitForThreads(self) -> None:
        """Wait for threads.

        Raises:
            TypeError: queue tried to process a malformed event
            AssertionError: scan halted for some reason
        """
        if not self.eventQueue:
            return

        counter = 0

        try:
            # start one thread for each module
            for mod in self.__moduleInstances.values():
                mod.start()
            final_passes = 3

            # watch for newly-generated events
            while True:

                # log status of threads every 10 iterations
                log_status = counter % 10 == 0
                counter += 1

                if log_status:
                    scanstatus = self.__dbh.scanInstanceGet(self.__scanId)
                    if scanstatus and scanstatus[5] == "ABORT-REQUESTED":
                        raise AssertionError("ABORT-REQUESTED")

                try:
                    sfEvent = self.eventQueue.get_nowait()
                    self.__sf.debug(f"waitForThreads() got event, {sfEvent.eventType}, from eventQueue.")
                except queue.Empty:
                    # check if we're finished
                    if self.threadsFinished(log_status):
                        sleep(.1)
                        # but are we really?
                        if self.threadsFinished(log_status):
                            if final_passes < 1:
                                break
                            # Trigger module.finished()
                            for mod in self.__moduleInstances.values():
                                if not mod.errorState and mod.incomingEventQueue is not None:
                                    mod.incomingEventQueue.put('FINISHED')
                            sleep(.1)
                            while not self.threadsFinished(log_status):
                                log_status = counter % 100 == 0
                                counter += 1
                                sleep(.01)
                            final_passes -= 1

                    else:
                        # save on CPU
                        sleep(.1)
                    continue

                if not isinstance(sfEvent, SpiderFootEvent):
                    raise TypeError(f"sfEvent is {type(sfEvent)}; expected SpiderFootEvent")

                # for every module
                for mod in self.__moduleInstances.values():
                    # if it's been aborted
                    if mod._stopScanning:
                        # break out of the while loop
                        raise AssertionError(f"{mod.__name__} requested stop")

                    # send it the new event if applicable
                    if not mod.errorState and mod.incomingEventQueue is not None:
                        watchedEvents = mod.watchedEvents()
                        if sfEvent.eventType in watchedEvents or "*" in watchedEvents:
                            mod.incomingEventQueue.put(deepcopy(sfEvent))

        finally:
            # tell the modules to stop
            for mod in self.__moduleInstances.values():
                mod._stopScanning = True
            self.__sharedThreadPool.shutdown(wait=True)

    def threadsFinished(self, log_status: bool = False) -> bool:
        """Check if all threads are complete.

        Args:
            log_status (bool): print thread queue status to debug log

        Returns:
            bool: True if all threads are finished
        """
        if self.eventQueue is None:
            return True

        modules_waiting = dict()
        for m in self.__moduleInstances.values():
            try:
                if m.incomingEventQueue is not None:
                    modules_waiting[m.__name__] = m.incomingEventQueue.qsize()
            except Exception:
                with suppress(Exception):
                    m.errorState = True
        modules_waiting = sorted(modules_waiting.items(), key=lambda x: x[-1], reverse=True)

        modules_running = []
        for m in self.__moduleInstances.values():
            try:
                if m.running:
                    modules_running.append(m.__name__)
            except Exception:
                with suppress(Exception):
                    m.errorState = True

        modules_errored = []
        for m in self.__moduleInstances.values():
            try:
                if m.errorState:
                    modules_errored.append(m.__name__)
            except Exception:
                with suppress(Exception):
                    m.errorState = True

        queues_empty = [qsize == 0 for m, qsize in modules_waiting]

        for mod in self.__moduleInstances.values():
            if mod.errorState and mod.incomingEventQueue is not None:
                self.__sf.debug(f"Clearing and unsetting incomingEventQueue for errored module {mod.__name__}.")
                with suppress(Exception):
                    while 1:
                        mod.incomingEventQueue.get_nowait()
                mod.incomingEventQueue = None

        if not modules_running and not queues_empty:
            self.__sf.debug("Clearing queues for stalled/aborted modules.")
            for mod in self.__moduleInstances.values():
                try:
                    while True:
                        mod.incomingEventQueue.get_nowait()
                except Exception:
                    pass

        if log_status:
            events_queued = ", ".join([f"{mod}: {qsize:,}" for mod, qsize in modules_waiting[:5] if qsize > 0])
            if not events_queued:
                events_queued = 'None'
            self.__sf.debug(f"Events queued: {sum([m[-1] for m in modules_waiting]):,} ({events_queued})")
            if modules_running:
                self.__sf.debug(f"Modules running: {len(modules_running):,} ({', '.join(modules_running)})")
            if modules_errored:
                self.__sf.debug(f"Modules errored: {len(modules_errored):,} ({', '.join(modules_errored)})")

        if all(queues_empty) and not modules_running:
            return True
        return False
