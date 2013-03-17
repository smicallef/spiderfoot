#-----------------------------------------------------------------
# Name:         sfscan
# Purpose:      Scanning control functionality
#
# Author:       Steve Micallef <steve@binarypool.com>
#
# Created:      11/03/2013
# Copyright:    (c) Steve Micallef 2013
# License:      GPL
#-----------------------------------------------------------------
import json
import threading
import traceback
import os
import time
import urllib2
import sys
from copy import deepcopy
from sfdb import SpiderFootDb
from sflib import SpiderFoot

# Controls all scanning activity
# Eventually change this to be able to control multiple scan instances
class SpiderFootScanner:
    moduleInstances = None
    status = "UNKNOWN"
    myId = None

    def __init__(self, name, target, moduleList, globalOpts, moduleOpts):
        self.config = deepcopy(globalOpts)
        self.sf = SpiderFoot(self.config)
        self.target = target
        self.moduleList = moduleList
        self.name = name

        return

    # Status of the currently running scan (if any)
    def scanStatus(self, id):
        if id != self.myId:
            return "UNKNOWN"
        return self.status  

    # Stop a scan (id variable is unnecessary for now given that only one simultaneous
    # scan is permitted.)
    def stopScan(self, id):
        if id != self.myId:
            return None

        if self.moduleInstances == None:
            return None

        for modName in self.moduleInstances.keys():
            self.moduleInstances[modName].stopScanning()

    # Start running a scan
    def startScan(self):
        self.moduleInstances = dict()
        dbh = SpiderFootDb(self.config)
        self.sf.setDbh(dbh)
        aborted = False

        # Create a unique ID for this scan and create it in the back-end DB.
        self.config['__guid__'] = dbh.scanInstanceGenGUID(self.target)
        self.sf.setScanId(self.config['__guid__'])
        self.myId = self.config['__guid__']
        dbh.scanInstanceCreate(self.config['__guid__'], self.name, self.target)
        dbh.scanInstanceSet(self.config['__guid__'], time.time() * 1000, None, 'STARTING')
        self.status = "STARTING"
        
        # Save the config current set for this scan
        self.config['_modulesenabled'] = self.moduleList
        dbh.scanConfigSet(self.config['__guid__'], self.sf.configSerialize(self.config))

        self.sf.status("Scan [" + self.config['__guid__'] + "] initiated.")
        # moduleList = list of modules the user wants to run
        try:
            for modName in self.moduleList:
                if modName == '':
                    continue

                module = __import__('modules.' + modName, globals(), locals(), [modName])
                mod = getattr(module, modName)()

                # A bit hacky: we pass the database object as part of the config. This
                # object should only be used by the internal SpiderFoot modules writing
                # to the database, which at present is only sfp_stor_db.
                # Individual modules cannot create their own SpiderFootDb instance or
                # we'll get database locking issues, so it all goes through this.
                self.config['__sfdb__'] = dbh

                # Set up the module
                # Configuration is a combined global config with module-specific options
                #modConfig = deepcopy(self.config)
                modConfig = self.config['__modules__'][modName]['opts']
                for opt in self.config.keys():
                    modConfig[opt] = self.config[opt]

                mod.clearListeners() # clear any listener relationships from the past
                mod.setup(self.sf, self.target, modConfig)
                self.moduleInstances[modName] = mod
                self.sf.status(modName + " module loaded.")

            # Register listener modules and then start all modules sequentially
            for module in self.moduleInstances.values():
                for listenerModule in self.moduleInstances.values():
                    # Careful not to register twice or you will get duplicate events
                    if listenerModule in module._listenerModules:
                        continue
                    # Note the absence of a check for whether a module can register
                    # to itself. That is intentional because some modules will
                    # act on their own notifications (e.g. sfp_dns)!
                    if listenerModule.watchedEvents() != None:
                        module.registerListener(listenerModule)

            dbh.scanInstanceSet(self.config['__guid__'], status='RUNNING')
            self.status = "RUNNING"
            # Start the modules sequentially.
            for module in self.moduleInstances.values():
                # Check in case the user requested to stop the scan between modules initializing
                if module.checkForStop():
                    dbh.scanInstanceSet(self.config['__guid__'], status='ABORTING')
                    self.status = "ABORTING"
                    aborted = True
                    break
                module.start()

            # Check if any of the modules ended due to being stopped
            for module in self.moduleInstances.values():
                if module.checkForStop():
                    aborted = True

            if aborted:
                self.sf.status("Scan [" + self.config['__guid__'] + "] aborted.")
                dbh.scanInstanceSet(self.config['__guid__'], None, time.time() * 1000, 'ABORTED')
                self.status = "ABORTED"
            else:
                self.sf.status("Scan [" + self.config['__guid__'] + "] completed.")
                dbh.scanInstanceSet(self.config['__guid__'], None, time.time() * 1000, 'FINISHED')
                self.status = "FINISHED"
        except Exception as e:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            self.sf.error("Unhandled exception encountered during scan. Please report this as a bug: " + \
                repr(traceback.format_exception(exc_type, exc_value, exc_traceback)), False)
            self.sf.status("Scan [" + self.config['__guid__'] + "] failed: " + str(e))
            dbh.scanInstanceSet(self.config['__guid__'], None, time.time() * 1000, 'ERROR-FAILED')
            self.status = "ERROR-FAILED"

        self.moduleInstances = None
        dbh.close()
        self.sf.setDbh(None)
        self.sf.setScanId(None)

