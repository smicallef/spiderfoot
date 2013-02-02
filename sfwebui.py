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
from mako.lookup import TemplateLookup
from mako.template import Template
from sfdb import SpiderFootDb

# Data providers called by front-end javascript
# Each name maps to the data provider interface below, e.g. scanlistData()
# provides data for calls to /scanlist (scanlist())
class SpiderFootDataProvider:
    config = None

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
        return json.dumps(retdata)

    def startScan(self, name, target, moduleList, moduleOpts):
        dbh = SpiderFootDb(self.config)
        moduleInstances = dict()

        # Take a copy of the configuration
        sfConfig = self.config
        # Create a unique ID for this scan and create it in the back-end DB.
        sfConfig['__guid__'] = dbh.scanInstanceGenGUID(target)
        dbh.scanInstanceCreate(sfConfig['__guid__'], name, target)
        dbh.scanInstanceSet(sfConfig['__guid__'], time.time() * 1000, None, 'STARTED')

        print "Scan [" + sfConfig['__guid__'] + "] initiated."
        # moduleList = list of modules the user wants to run
        for modName in moduleList:
            if modName == '':
                continue

            module = __import__('modules.' + modName, globals(), locals(), [modName])
            mod = getattr(module, modName)()

            # Build up config to consist of general and module-specific config
            # to override defaults within the module itself
            # *** Modules are not yet configurable via the UI ***
            sfConfig.update(moduleOpts)

            # A bit hacky: we pass the database object as part of the config. This
            # object should only be used by the internal SpiderFoot modules writing
            # to the database, which at present is only sfp_stor_db.
            # Individual modules cannot create their own SpiderFootDb instance or
            # we'll get database locking issues, so it all goes through this.
            sfConfig['__sfdb__'] = dbh

            # Set up the module
            mod.clearListeners() # clear any listener relationships from the past
            mod.setup(target, sfConfig)
            moduleInstances[modName] = mod
            print modName + " module loaded."

        # Register listener modules and then start all modules sequentially
        for module in moduleInstances.values():
            for listenerModule in moduleInstances.values():
                # Careful not to register twice or you will get duplicate events
                if listenerModule in module._listenerModules:
                   continue
                if listenerModule != module and listenerModule.watchedEvents() != None:
                    module.registerListener(listenerModule)

        # Start the modules sequentially.
        for module in moduleInstances.values():
            module.start()

        print "Scan [" + sfConfig['__guid__'] + "] completed."
        dbh.scanInstanceSet(sfConfig['__guid__'], None, time.time() * 1000, 'FINISHED')
        dbh.close()


class SpiderFootWebUi:
    dp = None
    lookup = TemplateLookup(directories=[''])

    def __init__(self, config):
        # Data provider will provide all data from the DB
        self.dp = SpiderFootDataProvider(config)
        self.config = config
        return

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
        return templ.render(id=id, name=res[0], pageid='SCANINFO')
    scaninfo.exposed = True

    def error(self, message):
        templ = Template(filename='dyn/error.tmpl', lookup=self.lookup)
        return templ.render(message=message)

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

    # Initiate a scan
    def startscan(self, scanname, scantarget, modulelist):
        modopts = dict()
        modlist = modulelist.replace('module_', '').split(',')

        # For now we don't permit multiple simultaneous scans
        for thread in threading.enumerate():
            if thread.name.startswith("SF_"):
                templ = Template(filename='dyn/newscan.tmpl', lookup=self.lookup)
                return templ.render(modules=self.config['__modules__'], alreadyRunning=True, runningScan=thread.name[3:]) 
        
        print "Spawning thread for new scan..."
        t = threading.Thread(name="SF_" + scanname, target=self.dp.startScan, args=(scanname, scantarget, modlist, modopts))
        t.start()
        templ = Template(filename='dyn/scanlist.tmpl', lookup=self.lookup)
        return templ.render(pageid='SCANLIST',newscan=scanname)
    startscan.exposed = True

    # Stop a scan
    def stopscan(self, id):
        return self.dp.stopScan(id)
    stopscan.exposed = True

