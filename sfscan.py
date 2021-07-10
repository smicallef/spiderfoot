# -*- coding: utf-8 -*-
# -----------------------------------------------------------------
# Name:         sfscan
# Purpose:      Scanning control functionality
#
# Author:       Steve Micallef <steve@binarypool.com>
#
# Created:      11/03/2013
# Copyright:    (c) Steve Micallef 2013
# License:      GPL
# -----------------------------------------------------------------
import socket
import sys
import time
import queue
import traceback
from time import sleep
from copy import deepcopy
from collections import OrderedDict

import dns.resolver

from sflib import SpiderFoot
from spiderfoot import SpiderFootDb, SpiderFootEvent, SpiderFootPlugin, SpiderFootTarget, SpiderFootHelpers


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

    def __init__(self, scanName, scanId, targetValue, targetType, moduleList, globalOpts, start=True):
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
            raise ValueError(f"Invalid target: {e}")

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
                if proxy_type == '4' or proxy_type == '5':
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

        # Get internet TLDs
        tlddata = self.__sf.cacheGet("internet_tlds", self.__config['_internettlds_cache'])

        # If it wasn't loadable from cache, load it from scratch
        if tlddata is None:
            self.__config['_internettlds'] = self.__sf.optValueToData(self.__config['_internettlds'])
            self.__sf.cachePut("internet_tlds", self.__config['_internettlds'])
        else:
            self.__config["_internettlds"] = tlddata.splitlines()

        self.__setStatus("INITIALIZING", time.time() * 1000, None)

        # Used when module threading is enabled
        self.eventQueue = None

        if start:
            self.__startScan()

    @property
    def scanId(self):
        return self.__scanId

    @property
    def status(self):
        return self.__status

    def __setStatus(self, status, started=None, ended=None):
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

    def __startScan(self, threaded=True):
        """Start running a scan.

        Args:
            threaded (bool): whether to thread modules
        """
        aborted = False

        self.__setStatus("STARTING", time.time() * 1000, None)
        self.__sf.status(f"Scan [{self.__scanId}] initiated.")

        if threaded:
            self.eventQueue = queue.Queue()

        try:
            # moduleList = list of modules the user wants to run
            for modName in self.__moduleList:
                if modName == '':
                    continue

                try:
                    module = __import__('modules.' + modName, globals(), locals(), [modName])
                except ImportError:
                    self.__sf.error(f"Failed to load module: {modName}")
                    continue

                mod = getattr(module, modName)()
                mod.__name__ = modName

                # Module may have been renamed or removed
                if modName not in self.__config['__modules__']:
                    continue

                # Set up the module
                # Configuration is a combined global config with module-specific options
                self.__modconfig[modName] = deepcopy(self.__config['__modules__'][modName]['opts'])
                for opt in list(self.__config.keys()):
                    self.__modconfig[modName][opt] = deepcopy(self.__config[opt])

                mod.clearListeners()  # clear any listener relationships from the past
                mod.setup(self.__sf, self.__modconfig[modName])
                mod.setDbh(self.__dbh)
                mod.setScanId(self.__scanId)

                # Give modules a chance to 'enrich' the original target with
                # aliases of that target.
                newTarget = mod.enrichTarget(self.__target)
                if newTarget is not None:
                    self.__target = newTarget
                self.__moduleInstances[modName] = mod

                # Override the module's local socket module
                # to be the SOCKS one.
                if self.__config['_socks1type'] != '':
                    mod._updateSocket(socket)

                # Set up event output filters if requested
                if self.__config['__outputfilter']:
                    mod.setOutputFilter(self.__config['__outputfilter'])

                # Register the target with the module
                mod.setTarget(self.__target)

                if threaded:
                    # Set up the outgoing event queue
                    mod.outgoingEventQueue = self.eventQueue
                    mod.incomingEventQueue = queue.Queue()

                self.__sf.status(modName + " module loaded.")

            # sort modules by priority
            self.__moduleInstances = OrderedDict(sorted(self.__moduleInstances.items(), key=lambda m: m[-1]._priority))

            if not threaded:
                # Register listener modules and then start all modules sequentially
                for module in list(self.__moduleInstances.values()):

                    for listenerModule in list(self.__moduleInstances.values()):
                        # Careful not to register twice or you will get duplicate events
                        if listenerModule in module._listenerModules:
                            continue
                        # Note the absence of a check for whether a module can register
                        # to itself. That is intentional because some modules will
                        # act on their own notifications (e.g. sfp_dns)!
                        if listenerModule.watchedEvents() is not None:
                            module.registerListener(listenerModule)

            # Now we are ready to roll..
            self.__setStatus("RUNNING")

            # Create a pseudo module for the root event to originate from
            psMod = SpiderFootPlugin()
            psMod.__name__ = "SpiderFoot UI"
            psMod.setTarget(self.__target)
            psMod.setDbh(self.__dbh)
            psMod.clearListeners()
            if threaded:
                psMod.outgoingEventQueue = self.eventQueue
                psMod.incomingEventQueue = queue.Queue()
            else:
                for mod in list(self.__moduleInstances.values()):
                    if mod.watchedEvents() is not None:
                        psMod.registerListener(mod)

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
            for mod in list(self.__moduleInstances.values()):
                if mod.checkForStop():
                    self.__setStatus('ABORTING')
                    aborted = True
                    break

            # start threads
            if threaded and not aborted:
                self.waitForThreads()

            if aborted:
                self.__sf.status(f"Scan [{self.__scanId}] aborted.")
                self.__setStatus("ABORTED", None, time.time() * 1000)
            else:
                self.__sf.status(f"Scan [{self.__scanId}] completed.")
                self.__setStatus("FINISHED", None, time.time() * 1000)
        except BaseException as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.__sf.error(f"Unhandled exception ({e.__class__.__name__}) encountered during scan."
                            + "Please report this as a bug: "
                            + repr(traceback.format_exception(exc_type, exc_value, exc_traceback)))
            self.__sf.status(f"Scan [{self.__scanId}] failed: {e}")
            self.__setStatus("ERROR-FAILED", None, time.time() * 1000)

        self.__dbh.close()

    def waitForThreads(self):
        counter = 0

        try:
            if not self.eventQueue:
                return

            # start one thread for each module
            for mod in self.__moduleInstances.values():
                mod.start()

            # watch for newly-generated events
            while True:

                # log status of threads every 100 iterations
                log_status = counter % 100 == 0
                counter += 1

                try:
                    sfEvent = self.eventQueue.get_nowait()
                    self.__sf.debug(f"waitForThreads() got event, {sfEvent.eventType}, from eventQueue.")
                except queue.Empty:
                    # check if we're finished
                    if self.threadsFinished(log_status):
                        sleep(.1)
                        # but are we really?
                        if self.threadsFinished(log_status):
                            break
                    else:
                        # save on CPU
                        sleep(.01)
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
                    watchedEvents = mod.watchedEvents()
                    if sfEvent.eventType in watchedEvents or "*" in watchedEvents:
                        mod.incomingEventQueue.put(deepcopy(sfEvent))

        except (KeyboardInterrupt, AssertionError) as e:
            self.__sf.status(f"Scan [{self.__scanId}] aborted, {e}.")

        finally:
            # tell the modules to stop
            for mod in self.__moduleInstances.values():
                mod._stopScanning = True

    def threadsFinished(self, log_status=False):
        if self.eventQueue is None:
            return True

        modules_waiting = {m.__name__: m.incomingEventQueue.qsize() for m in self.__moduleInstances.values()}
        modules_waiting = sorted(modules_waiting.items(), key=lambda x: x[-1], reverse=True)
        modules_running = [m.__name__ for m in self.__moduleInstances.values() if m.running]
        queues_empty = [qsize == 0 for m, qsize in modules_waiting]

        if not modules_running and not queues_empty:
            self.__sf.debug("Clearing queues for stalled/aborted modules.")
            for mod in self.__moduleInstances.values():
                try:
                    while True:
                        mod.incomingEventQueue.get_nowait()
                except Exception:
                    pass

        if log_status and modules_running:
            events_queued = ", ".join([f"{mod}: {qsize:,}" for mod, qsize in modules_waiting[:5] if qsize > 0])
            if events_queued:
                self.__sf.info(f"Events queued: {events_queued}")

        if all(queues_empty) and not modules_running:
            return True
        return False
