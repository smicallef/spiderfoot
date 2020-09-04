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
import traceback
from copy import deepcopy

import dns.resolver

from sflib import SpiderFoot
from spiderfoot import SpiderFootDb, SpiderFootEvent, SpiderFootPlugin, SpiderFootTarget


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
        if not isinstance(scanId, str):
            raise TypeError(f"scanId is {type(scanId)}; expected str()")

        if scanId:
            self.__scanId = scanId
        else:
            self.__scanId = self.__sf.genScanInstanceId()

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

        # If a SOCKS server was specified, set it up
        if self.__config['_socks1type']:
            socksAddr = self.__config['_socks2addr']
            socksPort = int(self.__config['_socks3port'])
            socksUsername = self.__config['_socks4user'] or ''
            socksPassword = self.__config['_socks5pwd'] or ''

            proxy = f"{socksAddr}:{socksPort}"

            if socksUsername or socksPassword:
                proxy = "%s:%s@%s" % (socksUsername, socksPassword, proxy)

            if self.__config['_socks1type'] == '4':
                proxy = 'socks4://' + proxy
            elif self.__config['_socks1type'] == '5':
                proxy = 'socks5://' + proxy
            elif self.__config['_socks1type'] == 'HTTP':
                proxy = 'http://' + proxy
            elif self.__config['_socks1type'] == 'TOR':
                proxy = 'socks5h://' + proxy
            else:
                raise ValueError(f"Invalid SOCKS proxy type: {self.__config['_socks1ttype']}")

            self.__sf.debug(f"SOCKS: {socksAddr}:{socksPort} ({socksUsername}:{socksPassword})")

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

        if start:
            self.__startScan()

    @property
    def scanId(self):
        """Unique identifier for this scan"""
        return self.__scanId

    @property
    def status(self):
        """Status of this scan"""
        return self.__status

    def __setStatus(self, status, started=None, ended=None):
        """Set the status of the currently running scan (if any).

        Args:
            status (str): scan status
            started (float): timestamp at start of scan
            ended (float): timestamp at end of scan

        Returns:
            None

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

    def __startScan(self):
        """Start running a scan."""

        aborted = False

        self.__setStatus("STARTING", time.time() * 1000, None)
        self.__sf.status(f"Scan [{self.__scanId}] initiated.")

        try:
            # moduleList = list of modules the user wants to run
            for modName in self.__moduleList:
                if modName == '':
                    continue

                try:
                    module = __import__('modules.' + modName, globals(), locals(), [modName])
                except ImportError:
                    self.__sf.error("Failed to load module: " + modName, False)
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

                self.__sf.status(modName + " module loaded.")

            # Register listener modules and then start all modules sequentially
            for module in list(self.__moduleInstances.values()):
                # Register the target with the module
                module.setTarget(self.__target)

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
            for module in list(self.__moduleInstances.values()):
                if module.checkForStop():
                    self.__setStatus('ABORTING')
                    aborted = True
                    break

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
                            + repr(traceback.format_exception(exc_type, exc_value, exc_traceback)), False)
            self.__sf.status(f"Scan [{self.__scanId}] failed: {e}")
            self.__setStatus("ERROR-FAILED", None, time.time() * 1000)

        self.__dbh.close()
