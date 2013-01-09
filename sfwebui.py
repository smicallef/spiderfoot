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
import cherrypy
import cgi
from mako.lookup import TemplateLookup
from mako.template import Template
import time
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

class SpiderFootWebUi:
    dp = None
    dbh = None
    lookup = TemplateLookup(directories=[''])

    def __init__(self, config):
        # Data provider will provide all data from the DB
        self.dp = SpiderFootDataProvider(config)
        return

    #
    # USER INTERFACE PAGES
    #
   
    # Main page listing scans available
    def index(self):
        # Look for referenced templates in the current directory only
        templ = Template(filename='dyn/scanlist.tmpl', lookup=self.lookup)
        return templ.render(pageid='SCANLIST')
    index.exposed = True

    # Information about a selected scan
    def scaninfo(self, id):
        templ = Template(filename='dyn/scaninfo.tmpl', lookup=self.lookup)
        return templ.render(id=id, pageid='SCANINFO')
    scaninfo.exposed = True

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
