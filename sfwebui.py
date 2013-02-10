#-----------------------------------------------------------------
# Name:         sfwebui
# Purpose:      User interface class for use with a web browser
#
# Author:       Steve Micallef <steve@binarypool.com>
#
# Created:      30/09/2012
# Copyright:    (c) Steve Micallef 2012
# License:      GPL
#-----------------------------------------------------------------
import json
import threading
import cherrypy
import cgi
import time
import urllib2
from copy import deepcopy
from mako.lookup import TemplateLookup
from mako.template import Template
from sfdb import SpiderFootDb
from sflib import SpiderFoot

# Data providers called by front-end javascript
# Each name maps to the data provider interface below, e.g. scanlistData()
# provides data for calls to /scanlist (scanlist())
class SpiderFootDataProvider:
    config = None
    moduleInstances = None

    def __init__(self, config):
        self.config = config
        return

    def scanlistData(self):
        dbh = SpiderFootDb(self.config)
        data = dbh.scanInstanceList()
        retdata = []
        for row in data:
            created = time.strftime("%d/%m/%Y", time.localtime(row[3]))
            if row[4] != 0:
                started = time.strftime("%d/%m/%Y", time.localtime(row[4]))
            else:
                started = "Not yet"

            if row[5] != 0:
                finished = time.strftime("%d/%m/%Y", time.localtime(row[5]))
            else:
                finished = "Not yet"
            retdata.append([row[0], row[1], row[2], created, started, finished, row[6], row[7]])
        return json.dumps(retdata)

    def scansummaryData(self, instanceId):
        dbh = SpiderFootDb(self.config)
        data = dbh.scanResultSummary(instanceId)
        retdata = []
        for row in data:
            lastseen = time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(row[2]))
            retdata.append([row[0], row[1], lastseen, row[3]])
        return json.dumps(retdata)

    def scaneventresultsData(self, instanceId, eventType):
        dbh = SpiderFootDb(self.config)
        data = dbh.scanResultEvent(instanceId, eventType)
        retdata = []
        for row in data:
            lastseen = time.strftime("%d/%m/%Y %H:%M:%S", time.localtime(row[0]))
            escaped = cgi.escape(row[1])
            retdata.append([lastseen, escaped, row[2], row[3]])
        return json.dumps(retdata, ensure_ascii=False)

    def startScan(self, name, target, moduleList, globalOpts, moduleOpts):
        dbh = SpiderFootDb(globalOpts)
        self.moduleInstances = dict()
        aborted = False

        # Take a copy of the configuration supplied
        sfConfig = deepcopy(globalOpts)
        # Create a unique ID for this scan and create it in the back-end DB.
        sfConfig['__guid__'] = dbh.scanInstanceGenGUID(target)
        dbh.scanInstanceCreate(sfConfig['__guid__'], name, target)
        dbh.scanInstanceSet(sfConfig['__guid__'], time.time() * 1000, None, 'STARTING')
        
        # Save the config current set for this scan
        sf = SpiderFoot(sfConfig)
        dbh.scanConfigSet(sfConfig['__guid__'], sf.configSerialize(sfConfig))

        print "Scan [" + sfConfig['__guid__'] + "] initiated."
        # moduleList = list of modules the user wants to run
        try:
            for modName in moduleList:
                if modName == '':
                    continue

                module = __import__('modules.' + modName, globals(), locals(), [modName])
                mod = getattr(module, modName)()

                # Build up config to consist of general and module-specific config
                # to override defaults within the module itself
                # *** Modules are not yet configurable via the UI ***
                #sfConfig.update(moduleOpts)

                # A bit hacky: we pass the database object as part of the config. This
                # object should only be used by the internal SpiderFoot modules writing
                # to the database, which at present is only sfp_stor_db.
                # Individual modules cannot create their own SpiderFootDb instance or
                # we'll get database locking issues, so it all goes through this.
                sfConfig['__sfdb__'] = dbh

                # Set up the module
                mod.clearListeners() # clear any listener relationships from the past
                mod.setup(target, sfConfig)
                self.moduleInstances[modName] = mod
                print modName + " module loaded."

            # Register listener modules and then start all modules sequentially
            for module in self.moduleInstances.values():
                for listenerModule in self.moduleInstances.values():
                    # Careful not to register twice or you will get duplicate events
                    if listenerModule in module._listenerModules:
                        continue
                    if listenerModule != module and listenerModule.watchedEvents() != None:
                        module.registerListener(listenerModule)

            dbh.scanInstanceSet(sfConfig['__guid__'], status='RUNNING')
            # Start the modules sequentially.
            for module in self.moduleInstances.values():
                # Check in case the user requested to stop the scan between modules initializing
                if module.checkForStop():
                    dbh.scanInstanceSet(sfConfig['__guid__'], status='ABORTING')
                    aborted = True
                    break
                module.start()

            # Check if any of the modules ended due to being stopped
            for module in self.moduleInstances.values():
                if module.checkForStop():
                    aborted = True

            if aborted:
                print "Scan [" + sfConfig['__guid__'] + "] aborted."
                dbh.scanInstanceSet(sfConfig['__guid__'], None, time.time() * 1000, 'ABORTED')
            else:
                print "Scan [" + sfConfig['__guid__'] + "] completed."
                dbh.scanInstanceSet(sfConfig['__guid__'], None, time.time() * 1000, 'FINISHED')
        except Exception as e:
            print "Scan [" + sfConfig['__guid__'] + "] failed: " + str(e)
            dbh.scanInstanceSet(sfConfig['__guid__'], None, time.time() * 1000, 'ERROR-FAILED')

        self.moduleInstances = None
        dbh.close()

class SpiderFootWebUi:
    dp = None
    lookup = TemplateLookup(directories=[''])
    defaultConfig = dict()

    def __init__(self, config):
        self.defaultConfig = deepcopy(config)
        # Data provider will provide all data from the DB
        self.dp = SpiderFootDataProvider(config)
        dbh = SpiderFootDb(config)
        # 'config' supplied will be the defaults, let's supplement them
        # now with any configuration which may have previously been
        # saved.
        sf = SpiderFoot(config)
        self.config = sf.configUnserialize(dbh.configGet(), config)

    #
    # USER INTERFACE PAGES
    #

    # Configure a new scan
    def newscan(self):
        templ = Template(filename='dyn/newscan.tmpl', lookup=self.lookup)
        return templ.render(pageid='NEWSCAN', modules=self.config['__modules__'])
    newscan.exposed = True

    # Main page listing scans available
    def index(self):
        # Look for referenced templates in the current directory only
        templ = Template(filename='dyn/scanlist.tmpl', lookup=self.lookup)
        return templ.render(pageid='SCANLIST')
    index.exposed = True

    # Information about a selected scan
    def scaninfo(self, id):
        dbh = SpiderFootDb(self.config)
        res = dbh.scanInstanceGet(id)
        if res == None:
            return self.error("Scan ID not found.")

        templ = Template(filename='dyn/scaninfo.tmpl', lookup=self.lookup)
        return templ.render(id=id, name=res[0], pageid='SCANLIST')
    scaninfo.exposed = True

    # Settings
    def opts(self):
        templ = Template(filename='dyn/opts.tmpl', lookup=self.lookup)
        return templ.render(opts=self.config, pageid='SETTINGS')
    opts.exposed = True

    def error(self, message):
        templ = Template(filename='dyn/error.tmpl', lookup=self.lookup)
        return templ.render(message=message)

    # Delete a scan
    def scandelete(self, id, confirm=None):
        dbh = SpiderFootDb(self.config)
        res = dbh.scanInstanceGet(id)
        if res == None:
            return self.error("Scan ID not found.")

        if confirm != None:
            dbh.scanInstanceDelete(id)
            raise cherrypy.HTTPRedirect("/")
        else:
            templ = Template(filename='dyn/scandelete.tmpl', lookup=self.lookup)
            return templ.render(id=id, name=res[0])
    scandelete.exposed = True

    #
    # DATA PROVIDERS
    #

    # Produce a list of scans
    def scanlist(self):
        return self.dp.scanlistData()
    scanlist.exposed = True

    # Summary of scan results
    def scansummary(self, id):
        return self.dp.scansummaryData(id)
    scansummary.exposed = True

    # Event results for a scan
    def scaneventresults(self, id, eventType):
        return self.dp.scaneventresultsData(id, eventType)
    scaneventresults.exposed = True

    # Save settings, also used to completely reset them to default
    def savesettings(self, allopts):
        try:
            dbh = SpiderFootDb(self.config)
            # Reset config to default
            if allopts == "RESET":
                dbh.configClear() # Clear it in the DB
                self.config = deepcopy(self.defaultConfig) # Clear in memory
            else:
                useropts = json.loads(allopts)
                currentopts = deepcopy(self.config)

                # Make a new config where the user options override
                # the current system config.
                sf = SpiderFoot(self.config)
                self.config = sf.configUnserialize(useropts, currentopts)
    
                dbh.configSet(sf.configSerialize(currentopts))
        except Exception as e:
            return self.error("Processing one or more of your inputs failed: " + str(e))

        templ = Template(filename='dyn/opts.tmpl', lookup=self.lookup)
        return templ.render(opts=self.config, pageid='SETTINGS', updated=True)
    savesettings.exposed = True

    # Initiate a scan
    def startscan(self, scanname, scantarget, modulelist):
        modopts = dict()

        if scanname == "" or scantarget == "" or modulelist == "":
            return self.error("Form incomplete.")

        modlist = modulelist.replace('module_', '').split(',')

        # For now we don't permit multiple simultaneous scans
        for thread in threading.enumerate():
            if thread.name.startswith("SF_"):
                templ = Template(filename='dyn/newscan.tmpl', lookup=self.lookup)
                return templ.render(modules=self.config['__modules__'], alreadyRunning=True, runningScan=thread.name[3:]) 
        
        # Start running a new scan
        print "Spawning thread for new scan..."
        t = threading.Thread(name="SF_" + scanname, target=self.dp.startScan, args=(scanname, scantarget, modlist, self.config, modopts))
        t.start()

        templ = Template(filename='dyn/scanlist.tmpl', lookup=self.lookup)
        return templ.render(pageid='SCANLIST',newscan=scanname)
    startscan.exposed = True

    # Stop a scan (id variable is unnecessary for now given that only one simultaneous
    # scan is permitted.)
    def stopscan(self, id):
        if self.dp.moduleInstances == None:
            return self.error("There are no scans running. A data consistency error for this scan probably exists. <a href='/scandelete?id=" + id + "&confirm=1'>Click here to delete it.</a>")

        for modName in self.dp.moduleInstances.keys():
            print "Signalling module " + modName + " to stop."
            self.dp.moduleInstances[modName].stopScanning()
        templ = Template(filename='dyn/scanlist.tmpl', lookup=self.lookup)
        return templ.render(pageid='SCANLIST',stoppedscan=True)
    stopscan.exposed = True

