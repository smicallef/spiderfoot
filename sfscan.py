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
import traceback
import time
import sys
import socket
import dns.resolver
import random
from copy import deepcopy
from sfdb import SpiderFootDb
from sflib import SpiderFoot, SpiderFootEvent, SpiderFootTarget, \
    SpiderFootPlugin

class SpiderFootScanner():
    def __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True):
        """Initialize SpiderFootScanner object.

        Args:
            scanName (str): name of the scan
            scanId (str): unique ID of the scan
            scanTarget (str): scan target
            targetType (str): scan target type
            moduleList (list): list of modules to run
            globalOpts (dict): scan options
            start (bool): start the scan immediately

        Returns:
            None

        Todo:
             Eventually change this to be able to control multiple scan instances
        """

        if not isinstance(scanName, str):
            raise TypeError("scanName is %s; expected str()" % type(scanName))
        if not isinstance(scanId, str):
            raise TypeError("scanId is %s; expected str()" % type(scanId))
        if not isinstance(scanTarget, str):
            raise TypeError("scanTarget is %s; expected str()" % type(scanTarget))
        if not isinstance(targetType, str):
            raise TypeError("targetType is %s; expected str()" % type(targetType))
        if not isinstance(moduleList, list):
            raise TypeError("moduleList is %s; expected list()" % type(moduleList))
        if not isinstance(globalOpts, dict):
            raise TypeError("globalOpts is %s; expected dict()" % type(globalOpts))
        if not globalOpts:
            raise ValueError("globalOpts is empty")

        self.moduleInstances = dict()
        self.config = deepcopy(globalOpts)
        self.sf = SpiderFoot(self.config)
        self.dbh = SpiderFootDb(self.config)
        self.targetValue = scanTarget
        self.targetType = targetType
        self.moduleList = moduleList
        self.modconfig = dict()
        self.scanName = scanName
        self.sf.setDbh(self.dbh)

        # Create a unique ID for this scan and create it in the back-end DB.
        self.scanId = scanId
        self.sf.setGUID(self.scanId)
        self.dbh.scanInstanceCreate(self.scanId, self.scanName, self.targetValue)

        # Create our target
        try:
            self.target = SpiderFootTarget(self.targetValue, self.targetType)
        except ValueError as e:
            self.sf.status("Scan [%s] failed: %s" % (self.scanId, e))
            self.setStatus("ERROR-FAILED", None, time.time() * 1000)
            raise ValueError("Invalid target: %s" % e)
        except TypeError as e:
            self.sf.status("Scan [%s] failed: %s" % (self.scanId, e))
            self.setStatus("ERROR-FAILED", None, time.time() * 1000)
            raise TypeError("Invalid target: %s" % e)

        # Save the config current set for this scan
        self.config['_modulesenabled'] = self.moduleList
        self.dbh.scanConfigSet(self.scanId, self.sf.configSerialize(deepcopy(self.config)))

        # Process global options that point to other places for data

        # If a SOCKS server was specified, set it up
        if self.config['_socks1type']:
            socksDns = self.config['_socks6dns']
            socksAddr = self.config['_socks2addr']
            socksPort = int(self.config['_socks3port'])
            socksUsername = self.config['_socks4user'] or ''
            socksPassword = self.config['_socks5pwd'] or ''

            proxy = "%s:%s" % (socksAddr, socksPort)

            if socksUsername or socksPassword:
                proxy = "%s:%s@%s" % (socksUsername, socksPassword, proxy)

            if self.config['_socks1type'] == '4':
                proxy = 'socks4://' + proxy
            elif self.config['_socks1type'] == '5':
                proxy = 'socks5://' + proxy
            elif self.config['_socks1type'] == 'HTTP':
                proxy = 'http://' + proxy
            elif self.config['_socks1type'] == 'TOR':
                proxy = 'socks5h://' + proxy
            else:
                raise ValueError("Invalid SOCKS proxy type: %s" % self.config["_socks1ttype"])

            self.sf.debug("SOCKS: %s:%s (%s:%s)" % (socksAddr, socksPort, socksUsername, socksPassword))

            self.sf.updateSocket(proxy)
        else:
            self.sf.revertSocket()

        # Override the default DNS server
        if self.config['_dnsserver']:
            res = dns.resolver.Resolver()
            res.nameservers = [self.config['_dnsserver']]
            dns.resolver.override_system_resolver(res)
        else:
            dns.resolver.restore_system_resolver()

        # Set the user agent
        self.config['_useragent'] = self.sf.optValueToData(self.config['_useragent'])

        # Get internet TLDs
        tlddata = self.sf.cacheGet("internet_tlds", self.config['_internettlds_cache'])

        # If it wasn't loadable from cache, load it from scratch
        if tlddata is None:
            self.config['_internettlds'] = self.sf.optValueToData(self.config['_internettlds'])
            self.sf.cachePut("internet_tlds", self.config['_internettlds'])
        else:
            self.config["_internettlds"] = tlddata.splitlines()

        self.setStatus("INITIALIZING", time.time() * 1000, None)

        if start:
            self.startScan()

    def getId(self):
        """Retrieve the unique scan identifier.

        Returns:
            str: scan id
        """
        if hasattr(self, 'scanId'):
            return self.scanId
        return None

    def setStatus(self, status, started=None, ended=None):
        """Set the status of the currently running scan (if any).

        Args:
            status (str): scan status
            started (str): TBD
            ended (str): TBD

        Returns:
            None
        """

        if status not in ["INITIALIZING", "STARTING", "STARTED", "RUNNING", "ABORT-REQUESTED", "ABORTED", "ABORTING", "FINISHED", "ERROR-FAILED"]:
            raise ValueError("Invalid scan status '%s'" % status)

        self.status = status
        self.dbh.scanInstanceSet(self.scanId, started, ended, status)
        return None

    def startScan(self):
        """Start running a scan."""

        aborted = False

        self.setStatus("STARTING", time.time() * 1000, None)
        self.sf.status("Scan [" + self.scanId + "] initiated.")

        try:
            # moduleList = list of modules the user wants to run
            for modName in self.moduleList:
                if modName == '':
                    continue

                try:
                    module = __import__('modules.' + modName, globals(), locals(),
                                        [modName])
                except ImportError:
                    self.sf.error("Failed to load module: " + modName, False)
                    continue

                mod = getattr(module, modName)()
                mod.__name__ = modName

                # Module may have been renamed or removed
                if modName not in self.config['__modules__']:
                    continue

                # Set up the module
                # Configuration is a combined global config with module-specific options
                self.modconfig[modName] = deepcopy(self.config['__modules__'][modName]['opts'])
                for opt in list(self.config.keys()):
                    self.modconfig[modName][opt] = deepcopy(self.config[opt])

                mod.clearListeners()  # clear any listener relationships from the past
                mod.setup(self.sf, self.modconfig[modName])
                mod.setDbh(self.dbh)
                mod.setScanId(self.scanId)

                # Give modules a chance to 'enrich' the original target with
                # aliases of that target.
                newTarget = mod.enrichTarget(self.target)
                if newTarget is not None:
                    self.target = newTarget
                self.moduleInstances[modName] = mod

                # Override the module's local socket module
                # to be the SOCKS one.
                if self.config['_socks1type'] != '':
                    mod._updateSocket(socket)

                # Set up event output filters if requested
                if self.config['__outputfilter']:
                    mod.setOutputFilter(self.config['__outputfilter'])

                self.sf.status(modName + " module loaded.")

            # Register listener modules and then start all modules sequentially
            for module in list(self.moduleInstances.values()):
                # Register the target with the module
                module.setTarget(self.target)

                for listenerModule in list(self.moduleInstances.values()):
                    # Careful not to register twice or you will get duplicate events
                    if listenerModule in module._listenerModules:
                        continue
                    # Note the absence of a check for whether a module can register
                    # to itself. That is intentional because some modules will
                    # act on their own notifications (e.g. sfp_dns)!
                    if listenerModule.watchedEvents() is not None:
                        module.registerListener(listenerModule)

            # Now we are ready to roll..
            self.setStatus("RUNNING")

            # Create a pseudo module for the root event to originate from
            psMod = SpiderFootPlugin()
            psMod.__name__ = "SpiderFoot UI"
            psMod.setTarget(self.target)
            psMod.setDbh(self.dbh)
            psMod.clearListeners()
            for mod in list(self.moduleInstances.values()):
                if mod.watchedEvents() is not None:
                    psMod.registerListener(mod)

            # Create the "ROOT" event which un-triggered modules will link events to
            rootEvent = SpiderFootEvent("ROOT", self.targetValue, "", None)
            psMod.notifyListeners(rootEvent)
            firstEvent = SpiderFootEvent(self.targetType, self.targetValue,
                                         "SpiderFoot UI", rootEvent)
            psMod.notifyListeners(firstEvent)

            # Special case.. check if an INTERNET_NAME is also a domain
            if self.targetType == 'INTERNET_NAME':
                if self.sf.isDomain(self.targetValue, self.config['_internettlds']):
                    firstEvent = SpiderFootEvent('DOMAIN_NAME', self.targetValue,
                                                 "SpiderFoot UI", rootEvent)
                    psMod.notifyListeners(firstEvent)

            # If in interactive mode, loop through this shared global variable
            # waiting for inputs, and process them until my status is set to
            # FINISHED.

            # Check in case the user requested to stop the scan between modules
            # initializing
            for module in list(self.moduleInstances.values()):
                if module.checkForStop():
                    self.setStatus('ABORTING')
                    aborted = True
                    break

            if aborted:
                self.sf.status("Scan [" + self.scanId + "] aborted.")
                self.setStatus("ABORTED", None, time.time() * 1000)
            else:
                self.sf.status("Scan [" + self.scanId + "] completed.")
                self.setStatus("FINISHED", None, time.time() * 1000)
        except BaseException as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.sf.error("Unhandled exception (" + e.__class__.__name__ + ") " + \
                             "encountered during scan. Please report this as a bug: " + \
                             repr(traceback.format_exception(exc_type, exc_value, exc_traceback)), False)
            self.sf.status("Scan [" + self.scanId + "] failed: " + str(e))
            self.setStatus("ERROR-FAILED", None, time.time() * 1000)

        self.dbh.close()
