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
import thread
import cherrypy
import cgi
import csv
import os
import time
import random
import urllib2
import re
from copy import deepcopy
from mako.lookup import TemplateLookup
from mako.template import Template
from sfdb import SpiderFootDb
from sflib import SpiderFoot, globalScanStatus
from sfscan import SpiderFootScanner
from StringIO import StringIO

class SpiderFootWebUi:
    lookup = TemplateLookup(directories=[''])
    defaultConfig = dict()
    config = dict()
    token = None

    def __init__(self, config):
        self.defaultConfig = deepcopy(config)
        dbh = SpiderFootDb(self.defaultConfig)
        # 'config' supplied will be the defaults, let's supplement them
        # now with any configuration which may have previously been
        # saved.
        sf = SpiderFoot(self.defaultConfig)
        self.config = sf.configUnserialize(dbh.configGet(), self.defaultConfig)

        if self.config['__webaddr'] == "0.0.0.0":
            addr = "<IP of this host>"
        else:
            addr = self.config['__webaddr']

        print ""
        print ""
        print "*************************************************************"
        print " Use SpiderFoot by starting your web browser of choice and "
        print " browse to http://" + addr + ":" + str(self.config['__webport'])
        print "*************************************************************"
        print ""
        print ""


    # Sanitize user input
    def cleanUserInput(self, inputList):
        ret = list()

        for item in inputList:
            c = cgi.escape(item, True)
            c = c.replace('\'', '&quot;')
            ret.append(c)

        return ret

    #
    # USER INTERFACE PAGES
    #

    # Get result data in CSV format
    def scaneventresultexport(self, id, type, dialect="excel"):
        dbh = SpiderFootDb(self.config)
        data = dbh.scanResultEvent(id, type)
        fileobj = StringIO()
        parser = csv.writer(fileobj, dialect=dialect)
        parser.writerow(["Updated", "Type", "Module", "Source", "Data"])
        for row in data:
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
            datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
            parser.writerow([lastseen, str(row[4]), str(row[3]), str(row[2]), datafield])
        cherrypy.response.headers['Content-Disposition'] = "attachment; filename=SpiderFoot.csv"
        cherrypy.response.headers['Content-Type'] = "application/csv"
        cherrypy.response.headers['Pragma'] = "no-cache"
        return fileobj.getvalue()
    scaneventresultexport.exposed = True

    # Configuration used for a scan
    def scanopts(self, id):
        ret = dict()
        dbh = SpiderFootDb(self.config)
        ret['config'] = dbh.scanConfigGet(id)
        ret['configdesc'] = dict()
        for key in ret['config'].keys():
            if ':' not in key:
                ret['configdesc'][key] = self.config['__globaloptdescs__'][key]
            else:
                [ modName, modOpt ] = key.split(':')
                if not modName in self.config['__modules__'].keys():
                    continue

                if not modOpt in self.config['__modules__'][modName]['optdescs'].keys():
                    continue

                ret['configdesc'][key] = self.config['__modules__'][modName]['optdescs'][modOpt]

        sf = SpiderFoot(self.config)
        meta = dbh.scanInstanceGet(id)
        if meta[3] != 0:
            started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(meta[3]))
        else:
            started = "Not yet"

        if meta[4] != 0:
            finished = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(meta[4]))
        else:
            finished = "Not yet"
        ret['meta'] = [meta[0], meta[1], meta[2], started, finished, meta[5]]

        return json.dumps(ret)
    scanopts.exposed = True

    # Configure a new scan
    def newscan(self):
        dbh = SpiderFootDb(self.config)
        types = dbh.eventTypes()
        templ = Template(filename='dyn/newscan.tmpl', lookup=self.lookup)
        return templ.render(pageid='NEWSCAN', types=types, 
            modules=self.config['__modules__'])
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
        return templ.render(id=id, name=res[0], status=res[5], 
            pageid="SCANLIST")
    scaninfo.exposed = True

    # Settings
    def opts(self):
        templ = Template(filename='dyn/opts.tmpl', lookup=self.lookup)
        self.token = random.randint(0, 99999999)
        return templ.render(opts=self.config, pageid='SETTINGS', token=self.token)
    opts.exposed = True

    # Generic error, but not exposed as not called directly
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
            return templ.render(id=id, name=res[0], pageid="SCANLIST")
    scandelete.exposed = True

    # Save settings, also used to completely reset them to default
    def savesettings(self, allopts, token):
        if str(token) != str(self.token):
            return self.error("Invalid token (" + str(self.token) + ").")

        try:
            dbh = SpiderFootDb(self.config)
            # Reset config to default
            if allopts == "RESET":
                dbh.configClear() # Clear it in the DB
                self.config = deepcopy(self.defaultConfig) # Clear in memory
            else:
                useropts = json.loads(allopts)
                cleanopts = dict()
                for opt in useropts.keys():
                    cleanopts[opt] = self.cleanUserInput([useropts[opt]])[0]

                currentopts = deepcopy(self.config)

                # Make a new config where the user options override
                # the current system config.
                sf = SpiderFoot(self.config)
                self.config = sf.configUnserialize(cleanopts, currentopts)
                dbh.configSet(sf.configSerialize(currentopts))
        except Exception as e:
            return self.error("Processing one or more of your inputs failed: " + str(e))

        templ = Template(filename='dyn/opts.tmpl', lookup=self.lookup)
        self.token = random.randint(0, 99999999)
        return templ.render(opts=self.config, pageid='SETTINGS', updated=True, 
            token=self.token)
    savesettings.exposed = True

    # Initiate a scan
    def startscan(self, scanname, scantarget, modulelist, typelist):
        global globalScanStatus

        # Snapshot the current configuration to be used by the scan
        cfg = deepcopy(self.config)
        modopts = dict() # Not used yet as module options are set globally
        modlist = list()
        sf = SpiderFoot(cfg)
        dbh = SpiderFootDb(cfg)
        types = dbh.eventTypes()
        targetType = None
        [scanname, scantarget] = self.cleanUserInput([scanname, scantarget])

        if scanname == "" or scantarget == "":
            return self.error("Form incomplete.")

        if typelist == "" and modulelist == "":
            return self.error("Form incomplete.")

        if modulelist != "":
            modlist = modulelist.replace('module_', '').split(',')
        else:
            typesx = typelist.replace('type_', '').split(',')
            # 1. Find all modules that produce the requested types
            modlist = sf.modulesProducing(typesx)
            newmods = deepcopy(modlist)
            newmodcpy = deepcopy(newmods)
            # 2. For each type those modules consume, get modules producing
            while len(newmodcpy) > 0:
                for etype in sf.eventsToModules(newmodcpy):
                    xmods = sf.modulesProducing([etype])
                    for mod in xmods:
                        if mod not in modlist:
                            modlist.append(mod)
                            newmods.append(mod)
                newmodcpy = deepcopy(newmods)
                newmods = list()

        # Add our mandatory storage module..
        if "sfp__stor_db" not in modlist:
            modlist.append("sfp__stor_db")
        modlist.sort()

        regexToType = {
            "^\d+\.\d+\.\d+\.\d+$": "IP_ADDRESS",
            "^\d+\.\d+\.\d+\.\d+/\d+$": "IP_SUBNET",
            "^.[a-zA-Z\-0-9\.]+$": "INTERNET_NAME"
        }

        # Parse the target and set the targetType
        for rx in regexToType.keys():
            if re.match(rx, scantarget, re.IGNORECASE):
                targetType = regexToType[rx]
                break

        if targetType == None:
            return self.error("Invalid target type. Could not recognize it as " + \
                "an IP address, IP subnet, domain name or host name.")

        # Start running a new scan
        scanId = sf.genScanInstanceGUID(scanname)
        t = SpiderFootScanner(scanname, scantarget.lower(), targetType, scanId, 
            modlist, cfg, modopts)
        t.start()

        # Wait until the scan has initialized
        while globalScanStatus.getStatus(scanId) == None:
            print "[info] Waiting for the scan to initialize..."
            time.sleep(1)

        templ = Template(filename='dyn/scaninfo.tmpl', lookup=self.lookup)
        return templ.render(id=scanId, name=scanname, 
            status=globalScanStatus.getStatus(scanId), pageid="SCANLIST")
    startscan.exposed = True

    # Stop a scan (id variable is unnecessary for now given that only one simultaneous
    # scan is permitted.)
    def stopscan(self, id):
        global globalScanStatus

        if globalScanStatus.getStatus(id) == None:
            return self.error("That scan is not actually running. A data consistency " + \
                "error for this scan probably exists. <a href='/scandelete?id=" + \
                id + "&confirm=1'>Click here to delete it.</a>")

        if globalScanStatus.getStatus(id) == "ABORTED":
            return self.error("The scan is already aborted.")

        if not globalScanStatus.getStatus(id) == "RUNNING":
            return self.error("The running scan is currently in the state '" + \
                globalScanStatus.getStatus(id) + "', please try again later or restart " + \
                " SpiderFoot.")

        globalScanStatus.setStatus(id, "ABORT-REQUESTED")
        templ = Template(filename='dyn/scanlist.tmpl', lookup=self.lookup)
        return templ.render(pageid='SCANLIST',stoppedscan=True)
    stopscan.exposed = True

    #
    # DATA PROVIDERS
    #

    # Scan log data
    def scanlog(self, id, limit=None):
        dbh = SpiderFootDb(self.config)
        data = dbh.scanLogs(id, limit)
        retdata = []
        for row in data:
            generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]/1000))
            retdata.append([generated, row[1], row[2], 
                cgi.escape(unicode(row[3], errors='replace'))])
        return json.dumps(retdata)
    scanlog.exposed = True

    # Scan error data
    def scanerrors(self, id, limit=None):
        dbh = SpiderFootDb(self.config)
        data = dbh.scanErrors(id, limit)
        retdata = []
        for row in data:
            generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]/1000))
            retdata.append([generated, row[1],
                cgi.escape(unicode(row[2], errors='replace'))])
        return json.dumps(retdata)
    scanerrors.exposed = True

    # Produce a list of scans
    def scanlist(self):
        dbh = SpiderFootDb(self.config)
        data = dbh.scanInstanceList()
        retdata = []
        for row in data:
            created = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[3]))
            if row[4] != 0:
                started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[4]))
            else:
                started = "Not yet"

            if row[5] != 0:
                finished = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[5]))
            else:
                finished = "Not yet"
            retdata.append([row[0], row[1], row[2], created, started, finished, row[6], row[7]])
        return json.dumps(retdata)
    scanlist.exposed = True

    # Basic information about a scan
    def scanstatus(self, id):
        dbh = SpiderFootDb(self.config)
        data = dbh.scanInstanceGet(id)
        created = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data[2]))
        started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data[3]))
        ended = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data[4]))

        retdata = [data[0], data[1], created, started, ended, data[5]]
        return json.dumps(retdata)
    scanstatus.exposed = True

    # Summary of scan results
    def scansummary(self, id):
        dbh = SpiderFootDb(self.config)
        data = dbh.scanResultSummary(id)
        retdata = []
        for row in data:
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[2]))
            retdata.append([row[0], row[1], lastseen, row[3], row[4]])
        return json.dumps(retdata)
    scansummary.exposed = True

    # Event results for a scan
    def scaneventresults(self, id, eventType):
        dbh = SpiderFootDb(self.config)
        data = dbh.scanResultEvent(id, eventType)
        retdata = []
        for row in data:
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
            escapeddata = cgi.escape(row[1])
            escapedsrc = cgi.escape(row[2])
            retdata.append([lastseen, escapeddata, escapedsrc, 
                row[3], row[5], row[6], row[7], row[8]])
        return json.dumps(retdata, ensure_ascii=False)
    scaneventresults.exposed = True

    # Unique event results for a scan
    def scaneventresultsunique(self, id, eventType):
        dbh = SpiderFootDb(self.config)
        data = dbh.scanResultEventUnique(id, eventType)
        retdata = []
        for row in data:
            escaped = cgi.escape(row[0])
            retdata.append([escaped, row[1], row[2]])
        return json.dumps(retdata, ensure_ascii=False)
    scaneventresultsunique.exposed = True

    # Historical data for the scan, graphs will be rendered in JS
    def scanhistory(self, id):
        dbh = SpiderFootDb(self.config)
        data = dbh.scanResultHistory(id)
        return json.dumps(data, ensure_ascii=False)
    scanhistory.exposed = True

    def scanelementtypediscovery(self, id, eventType):
        keepGoing = True
        sf = SpiderFoot(self.config)
        dbh = SpiderFootDb(self.config)
        pc = dict()
        datamap = dict()

        # Get the events we will be tracing back from
        leafSet = dbh.scanResultEvent(id, eventType)

        # Get the first round of source IDs for the leafs
        nextIds = list()
        for row in leafSet:
            # these must be unique values!
            parentId = row[9]
            childId = row[8]
            datamap[childId] = row

            if pc.has_key(parentId):
                if childId not in pc[parentId]:
                    pc[parentId].append(childId)
            else:
                pc[parentId] = [ childId ]

            # parents of the leaf set
            if parentId not in nextIds:
                nextIds.append(parentId)

        while keepGoing:
            #print "Next IDs: " + str(nextIds)
            parentSet = dbh.scanElementSources(id, nextIds)
            nextIds = list()
            keepGoing = False

            for row in parentSet:
                parentId = row[9]
                childId = row[8]
                datamap[childId] = row

                # Prevent us from looping at root
                # 0 = event_hash and 3 = source_event_hash
                if row[8] == "ROOT" and row[9] == "ROOT":
                    continue

                if pc.has_key(parentId):
                    if childId not in pc[parentId]:
                        pc[parentId].append(childId)
                else:
                    pc[parentId] = [ childId ]
                if parentId not in nextIds:
                    nextIds.append(parentId)
                # Stop until we've found ROOT
                # 3 = source_event_hash
                if row[3] != "ROOT":
                    keepGoing = True

        #print pc
        retdata = dict()
        retdata['tree'] = sf.dataParentChildToTree(pc)
        retdata['data'] = datamap
        return json.dumps(retdata, ensure_ascii=False)
    scanelementtypediscovery.exposed = True
