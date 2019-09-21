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
import socks
import socket
import dns.resolver
import threading
import random
from copy import deepcopy, copy
from sfdb import SpiderFootDb
from sflib import SpiderFoot, SpiderFootEvent, SpiderFootTarget, \
    SpiderFootPlugin, globalScanStatus

# Eventually change this to be able to control multiple scan instances
class SpiderFootScanner(threading.Thread):
    # Thread-safe storage
    ts = None
    # Temporary storage
    temp = None

    # moduleOpts not yet used
    def __init__(self, scanName, scanTarget, targetType, scanId, moduleList,
                 globalOpts, moduleOpts):

        # Initialize the thread
        threading.Thread.__init__(self, name="SF_" + scanId + \
                                             str(random.SystemRandom().randint(100000, 999999)))

        # Temporary data to be used in startScan
        self.temp = dict()
        self.temp['config'] = deepcopy(globalOpts)
        self.temp['targetValue'] = scanTarget
        self.temp['targetType'] = targetType
        self.temp['moduleList'] = moduleList
        self.temp['scanName'] = scanName
        self.temp['scanId'] = scanId

    # Set the status of the currently running scan (if any)
    def setStatus(self, status, started=None, ended=None):
        if self.ts is None:
            print("Internal Error: Status set attempted before " + \
                  "SpiderFootScanner was ready.")
            exit(-1)

        self.ts.status = status
        self.ts.dbh.scanInstanceSet(self.ts.scanId, started, ended, status)
        globalScanStatus.setStatus(self.ts.scanId, status)
        return None

    def run(self):
        self.startScan()

    def getId(self):
        if hasattr(self.ts, 'scanId'):
            return self.ts.scanId
        return None

    # Start running a scan
    def startScan(self):
        global globalScanStatus

        self.ts = threading.local()
        self.ts.moduleInstances = dict()
        self.ts.sf = SpiderFoot(self.temp['config'])
        self.ts.config = deepcopy(self.temp['config'])
        self.ts.dbh = SpiderFootDb(self.temp['config'])
        self.ts.targetValue = self.temp['targetValue']
        self.ts.targetType = self.temp['targetType']
        self.ts.moduleList = self.temp['moduleList']
        self.ts.modconfig = dict()
        self.ts.scanName = self.temp['scanName']
        self.ts.scanId = self.temp['scanId']
        aborted = False
        self.ts.sf.setDbh(self.ts.dbh)

        # Create a unique ID for this scan and create it in the back-end DB.
        self.ts.sf.setGUID(self.ts.scanId)
        self.ts.dbh.scanInstanceCreate(self.ts.scanId,
                                       self.ts.scanName, self.ts.targetValue)
        self.setStatus("STARTING", time.time() * 1000, None)
        # Create our target
        target = SpiderFootTarget(self.ts.targetValue, self.ts.targetType)

        # Save the config current set for this scan
        self.ts.config['_modulesenabled'] = self.ts.moduleList
        self.ts.dbh.scanConfigSet(self.ts.scanId,
                                  self.ts.sf.configSerialize(deepcopy(self.ts.config)))

        self.ts.sf.status("Scan [" + self.ts.scanId + "] initiated.")
        # moduleList = list of modules the user wants to run
        try:
            # Process global options that point to other places for data

            # Save default socket methods that will be overridden
            if not hasattr(socket, 'savedsocket'):
                socket.savedsocket = socket.socket
                socket.savedcreate_connection = socket.create_connection
                #socket.savedgetaddrinfo = socket.getaddrinfo

            # If a SOCKS server was specified, set it up
            if self.ts.config['_socks1type'] != '':
                socksType = socks.PROXY_TYPE_SOCKS4
                socksDns = self.ts.config['_socks6dns']
                socksAddr = self.ts.config['_socks2addr']
                socksPort = int(self.ts.config['_socks3port'])
                socksUsername = ''
                socksPassword = ''

                if self.ts.config['_socks1type'] == '4':
                    socksType = socks.PROXY_TYPE_SOCKS4
                if self.ts.config['_socks1type'] == '5':
                    socksType = socks.PROXY_TYPE_SOCKS5
                    socksUsername = self.ts.config['_socks4user']
                    socksPassword = self.ts.config['_socks5pwd']

                if self.ts.config['_socks1type'] == 'HTTP':
                    socksType = socks.PROXY_TYPE_HTTP

                if self.ts.config['_socks1type'] == 'TOR':
                    socksType = socks.PROXY_TYPE_SOCKS5

                self.ts.sf.debug("SOCKS: " + socksAddr + ":" + str(socksPort) + \
                                 "(" + socksUsername + ":" + socksPassword + ")")
                socks.setdefaultproxy(socksType, socksAddr, socksPort,
                                      socksDns, socksUsername, socksPassword)

                # Override the default socket and getaddrinfo calls with the 
                # SOCKS ones. Just ensure we don't also try and SOCKS-proxy
                # connectivity to the TOR control port.
                def _create_connection(address, timeout=None, source_address=None):
                    if socksAddr not in address:
                        sock = socks.socksocket()
                        sock.setproxy(socks.PROXY_TYPE_SOCKS5, socksAddr, socksPort)
                        sock.settimeout(self.ts.config['_fetchtimeout'])
                        sock.connect(address)
                        return sock
                    else:
                        sock = socket.socket
                        sock.settimeout(self.ts.config['_fetchtimeout'])
                        sock.connect(address)
                        return sock

                socket.socket = socks.socksocket
                socket.setdefaulttimeout(self.ts.config['_fetchtimeout'])
                socket.create_connection = _create_connection
                #socket.getaddrinfo = socks.getaddrinfo
                self.ts.sf.updateSocket(socket)
            else:
                # BUG: If the user had a SOCKS proxy set
                # and then decided to unset it, the original socket class
                # is not reverted to its default state - we still have
                # the SOCKS version of socket.
                socket.socket = socket.savedsocket
                socket.setdefaulttimeout(self.ts.config['_fetchtimeout'])
                socket.create_connection = socket.savedcreate_connection
                #socket.getaddrinfo = socket.savedgetaddrinfo
                self.ts.sf.revertSocket()

            # Override the default DNS server
            if self.ts.config['_dnsserver'] != "":
                res = dns.resolver.Resolver()
                res.nameservers = [self.ts.config['_dnsserver']]
                dns.resolver.override_system_resolver(res)
            else:
                dns.resolver.restore_system_resolver()

            # Set the user agent
            self.ts.config['_useragent'] = self.ts.sf.optValueToData(
                self.ts.config['_useragent'])

            # Get internet TLDs
            tlddata = self.ts.sf.cacheGet("internet_tlds",
                                          self.ts.config['_internettlds_cache'])
            # If it wasn't loadable from cache, load it from scratch
            if tlddata is None:
                self.ts.config['_internettlds'] = self.ts.sf.optValueToData(
                    self.ts.config['_internettlds'])
                self.ts.sf.cachePut("internet_tlds", self.ts.config['_internettlds'])
            else:
                self.ts.config["_internettlds"] = tlddata.splitlines()

            for modName in self.ts.moduleList:
                if modName == '':
                    continue

                try:
                    module = __import__('modules.' + modName, globals(), locals(),
                                        [modName])
                except ImportError:
                    self.ts.sf.error("Failed to load module: " + modName, False)
                    continue

                mod = getattr(module, modName)()
                mod.__name__ = modName

                # Module may have been renamed or removed
                if modName not in self.ts.config['__modules__']:
                    continue

                # Set up the module
                # Configuration is a combined global config with module-specific options
                self.ts.modconfig[modName] = deepcopy(self.ts.config['__modules__'][modName]['opts'])
                for opt in self.ts.config.keys():
                    self.ts.modconfig[modName][opt] = deepcopy(self.ts.config[opt])

                mod.clearListeners()  # clear any listener relationships from the past
                mod.setup(self.ts.sf, self.ts.modconfig[modName])
                mod.setDbh(self.ts.dbh)
                mod.setScanId(self.ts.scanId)

                # Give modules a chance to 'enrich' the original target with
                # aliases of that target.
                newTarget = mod.enrichTarget(target)
                if newTarget is not None:
                    target = newTarget
                self.ts.moduleInstances[modName] = mod

                # Override the module's local socket module
                # to be the SOCKS one.
                if self.ts.config['_socks1type'] != '':
                    mod._updateSocket(socket)

                # Set up event output filters if requested
                if self.ts.config['__outputfilter']:
                    mod.setOutputFilter(self.ts.config['__outputfilter'])

                self.ts.sf.status(modName + " module loaded.")

            # Register listener modules and then start all modules sequentially
            for module in self.ts.moduleInstances.values():
                # Register the target with the module
                module.setTarget(target)

                for listenerModule in self.ts.moduleInstances.values():
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
            psMod.setTarget(target)
            psMod.clearListeners()
            for mod in self.ts.moduleInstances.values():
                if mod.watchedEvents() is not None:
                    psMod.registerListener(mod)

            # Create the "ROOT" event which un-triggered modules will link events to
            rootEvent = SpiderFootEvent("ROOT", self.ts.targetValue, "", None)
            psMod.notifyListeners(rootEvent)
            firstEvent = SpiderFootEvent(self.ts.targetType, self.ts.targetValue,
                                         "SpiderFoot UI", rootEvent)
            psMod.notifyListeners(firstEvent)

            # If in interactive mode, loop through this shared global variable
            # waiting for inputs, and process them until my status is set to
            # FINISHED.

            # Check in case the user requested to stop the scan between modules 
            # initializing
            for module in self.ts.moduleInstances.values():
                if module.checkForStop():
                    self.setStatus('ABORTING')
                    aborted = True
                    break

            if aborted:
                self.ts.sf.status("Scan [" + self.ts.scanId + "] aborted.")
                self.setStatus("ABORTED", None, time.time() * 1000)
            else:
                self.ts.sf.status("Scan [" + self.ts.scanId + "] completed.")
                self.setStatus("FINISHED", None, time.time() * 1000)
        except BaseException as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.ts.sf.error("Unhandled exception (" + e.__class__.__name__ + ") " + \
                             "encountered during scan. Please report this as a bug: " + \
                             repr(traceback.format_exception(exc_type, exc_value, exc_traceback)), False)
            self.ts.sf.status("Scan [" + self.ts.scanId + "] failed: " + str(e))
            self.setStatus("ERROR-FAILED", None, time.time() * 1000)

        self.ts.dbh.close()
        del self.ts
        del self.temp
