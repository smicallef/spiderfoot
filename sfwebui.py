# -*- coding: utf-8 -*-
# -----------------------------------------------------------------
# Name:         sfwebui
# Purpose:      User interface class for use with a web browser
#
# Author:       Steve Micallef <steve@binarypool.com>
#
# Created:      30/09/2012
# Copyright:    (c) Steve Micallef 2012
# License:      GPL
# -----------------------------------------------------------------
import json
import cherrypy
import html
import csv
import time
import random
import multiprocessing as mp
from secure import SecureHeaders
from cherrypy import _cperror
from operator import itemgetter
from copy import deepcopy
from mako.lookup import TemplateLookup
from mako.template import Template
from sfdb import SpiderFootDb
from sflib import SpiderFoot
from sfscan import SpiderFootScanner
from io import StringIO
mp.set_start_method("spawn", force=True)

class SpiderFootWebUi:
    lookup = TemplateLookup(directories=[''])
    defaultConfig = dict()
    config = dict()
    token = None
    docroot = ''

    def __init__(self, config):
        if not isinstance(config, dict):
            raise TypeError("config is %s; expected dict()" % type(config))
        if not config:
            raise ValueError("config is empty")

        self.defaultConfig = deepcopy(config)
        dbh = SpiderFootDb(self.defaultConfig)
        # 'config' supplied will be the defaults, let's supplement them
        # now with any configuration which may have previously been
        # saved.
        sf = SpiderFoot(self.defaultConfig)
        self.config = sf.configUnserialize(dbh.configGet(), self.defaultConfig)

        if self.config['__webaddr'] == "0.0.0.0": # nosec
            addr = "<IP of this host>"
        else:
            addr = self.config['__webaddr']

        self.docroot = self.config['__docroot'].rstrip('/')

        cherrypy.config.update({
          'error_page.404': self.error_page_404,
          'request.error_response': self.error_page
        })

        secure_headers = SecureHeaders(
            server="server",
            cache=False,
            csp="default-src 'self' ; script-src 'self' 'unsafe-inline' blob: ; style-src 'self' 'unsafe-inline' ; img-src 'self' data:"
        )

        cherrypy.config.update({
            "tools.response_headers.on": True,
            "tools.response_headers.headers": secure_headers.cherrypy()
        })

        if (cherrypy.server.ssl_certificate != None and cherrypy.server.ssl_private_key != None):
            url = "https://%s:%s%s" % (addr, self.config['__webport'], self.docroot)
        else:
            url = "http://%s:%s%s" % (addr, self.config['__webport'], self.docroot)

        print("")
        print("")
        print("*************************************************************")
        print(" Use SpiderFoot by starting your web browser of choice and ")
        print(" browse to %s" % url)
        print("*************************************************************")
        print("")
        print("")

    def error_page(self):
        cherrypy.response.status = 500

        if self.config['_debug']:
            cherrypy.response.body = _cperror.get_error_page(status=500, traceback=_cperror.format_exc())
        else:
            cherrypy.response.body = '<html><body>Error</body></html>'

    def error_page_404(self, status, message, traceback, version):
        templ = Template(filename='dyn/error.tmpl', lookup=self.lookup)
        return templ.render(message='Not Found', docroot=self.docroot, status=status)

    def cleanUserInput(self, inputList):
        """Sanitize user input, poorly.

        Args:
            inputList (list): TBD

        Returns:
            list: sanitized input
        """

        if not isinstance(inputList, list):
            raise TypeError("inputList is %s; expected list()" % type(inputList))

        ret = list()

        for item in inputList:
            c = html.escape(item, True)
            c = c.replace('\'', '&quot;')
            # We don't actually want & translated to &amp;
            c = c.replace("&amp;", "&").replace("&quot;", "\"")
            ret.append(c)

        return ret

    def searchBase(self, id=None, eventType=None, value=None):
        """Search

        Args:
            id: TBD
            eventType: TBD
            value: TBD

        Returns:
            list: search results
        """

        retdata = []

        regex = ""
        if [id, eventType, value].count('') == 3 or \
                        [id, eventType, value].count(None) == 3:
            return retdata

        if value.startswith("/") and value.endswith("/"):
            regex = value[1:len(value) - 1]
            value = ""

        value = value.replace('*', '%')
        if value in [None, ""] and regex in [None, ""]:
            value = "%"
            regex = ""

        dbh = SpiderFootDb(self.config)
        criteria = {
            'scan_id': None if id == '' else id,
            'type': None if eventType == '' else eventType,
            'value': None if value == '' else value,
            'regex': None if regex == '' else regex
        }

        try:
            data = dbh.search(criteria)
        except:
            return retdata

        for row in data:
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
            escapeddata = html.escape(row[1])
            escapedsrc = html.escape(row[2])
            retdata.append([lastseen, escapeddata, escapedsrc,
                            row[3], row[5], row[6], row[7], row[8], row[10],
                            row[11], row[4], row[13], row[14]])

        return retdata

    #
    # USER INTERFACE PAGES
    #

    def scaneventresultexport(self, id, type, dialect="excel"):
        """Get scan event result data in CSV format

        Args:
            id (str): scan ID
            type (str): TBD
            dialect (str): TBD

        Returns:
            string: results in CSV format
        """

        dbh = SpiderFootDb(self.config)
        data = dbh.scanResultEvent(id, type)
        fileobj = StringIO()
        parser = csv.writer(fileobj, dialect=dialect)
        parser.writerow(["Updated", "Type", "Module", "Source", "F/P", "Data"])
        for row in data:
            if row[4] == "ROOT":
                continue
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
            datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
            parser.writerow([lastseen, str(row[4]), str(row[3]), str(row[2]), row[13], datafield])
        cherrypy.response.headers['Content-Disposition'] = "attachment; filename=SpiderFoot.csv"
        cherrypy.response.headers['Content-Type'] = "application/csv"
        cherrypy.response.headers['Pragma'] = "no-cache"
        return fileobj.getvalue().encode("utf-8")

    scaneventresultexport.exposed = True

    def scaneventresultexportmulti(self, ids, dialect="excel"):
        """Get scan event result data in CSV format for multiple scans

        Args:
            ids (str): comma separated list of scan IDs
            dialect (str): TBD

        Returns:
            string: results in CSV format
        """

        dbh = SpiderFootDb(self.config)
        scaninfo = dict()
        data = list()
        for id in ids.split(','):
            scaninfo[id] = dbh.scanInstanceGet(id)
            data = data + dbh.scanResultEvent(id)

        fileobj = StringIO()
        parser = csv.writer(fileobj, dialect=dialect)
        parser.writerow(["Scan Name", "Updated", "Type", "Module", "Source", "F/P", "Data"])
        for row in data:
            if row[4] == "ROOT":
                continue
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
            datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
            parser.writerow([scaninfo[row[12]][0], lastseen, str(row[4]), str(row[3]),
                            str(row[2]), row[13], datafield])
        cherrypy.response.headers['Content-Disposition'] = "attachment; filename=SpiderFoot.csv"
        cherrypy.response.headers['Content-Type'] = "application/csv"
        cherrypy.response.headers['Pragma'] = "no-cache"
        return fileobj.getvalue().encode("Utf-8")

    scaneventresultexportmulti.exposed = True

    # Get search result data in CSV format
    def scansearchresultexport(self, id, eventType=None, value=None, dialect="excel"):
        data = self.searchBase(id, eventType, value)
        fileobj = StringIO()
        parser = csv.writer(fileobj, dialect=dialect)
        parser.writerow(["Updated", "Type", "Module", "Source", "F/P", "Data"])
        if not data:
            return None
        for row in data:
            if row[10] == "ROOT":
                continue
            datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
            parser.writerow([row[0], str(row[10]), str(row[3]), str(row[2]), row[11], datafield])
        cherrypy.response.headers['Content-Disposition'] = "attachment; filename=SpiderFoot.csv"
        cherrypy.response.headers['Content-Type'] = "application/csv"
        cherrypy.response.headers['Pragma'] = "no-cache"
        return fileobj.getvalue().encode("Utf-8")

    scansearchresultexport.exposed = True

    # Export results from multiple scans in JSON format
    def scanexportjsonmulti(self, ids):
        dbh = SpiderFootDb(self.config)
        scaninfo = list()
        scan_name = ""

        for id in ids.split(','):
            scan = dbh.scanInstanceGet(id)

            if scan is None:
                continue

            scan_name = scan[0]

            for row in dbh.scanResultEvent(id):
                lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
                event_data = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
                source_data = str(row[2])
                source_module = str(row[3])
                event_type = row[4]
                false_positive = row[13]

                if event_type == "ROOT":
                    continue

                scaninfo.append({
                    "data": event_data,
                    "event_type": event_type,
                    "module": source_module,
                    "source_data": source_data,
                    "false_positive": false_positive,
                    "last_seen": lastseen,
                    "scan_name": scan_name,
                    "scan_target": scan[1]
                })

        if len(ids.split(',')) > 1 or scan_name == "":
            fname = "SpiderFoot.json"
        else:
            fname = scan_name + "-SpiderFoot.json"

        cherrypy.response.headers['Content-Disposition'] = "attachment; filename=" + fname
        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"
        cherrypy.response.headers['Pragma'] = "no-cache"
        return json.dumps(scaninfo).encode("utf-8")

    scanexportjsonmulti.exposed = True

    # Export entities from scan results for visualising
    def scanviz(self, id, gexf="0"):
        dbh = SpiderFootDb(self.config)
        sf = SpiderFoot(self.config)
        data = dbh.scanResultEvent(id, filterFp=True)
        scan = dbh.scanInstanceGet(id)
        root = scan[1]
        if gexf != "0":
            cherrypy.response.headers['Content-Disposition'] = "attachment; filename=SpiderFoot.gexf"
            cherrypy.response.headers['Content-Type'] = "application/gexf"
            cherrypy.response.headers['Pragma'] = "no-cache"
            return sf.buildGraphGexf([root], "SpiderFoot Export", data)
        else:
            return sf.buildGraphJson([root], data)

    scanviz.exposed = True

    # Export entities results from multiple scans in GEXF format
    def scanvizmulti(self, ids, gexf="1"):
        dbh = SpiderFootDb(self.config)
        sf = SpiderFoot(self.config)
        data = list()
        roots = list()
        for id in ids.split(','):
            data = data + dbh.scanResultEvent(id, filterFp=True)
            roots.append(dbh.scanInstanceGet(id)[1])

        if gexf != "0":
            cherrypy.response.headers['Content-Disposition'] = "attachment; filename=SpiderFoot.gexf"
            cherrypy.response.headers['Content-Type'] = "application/gexf"
            cherrypy.response.headers['Pragma'] = "no-cache"
            return sf.buildGraphGexf(roots, "SpiderFoot Export", data)
        else:
            # Not implemented yet
            return None

    scanvizmulti.exposed = True


    # Configuration used for a scan
    def scanopts(self, id):
        ret = dict()
        dbh = SpiderFootDb(self.config)
        ret['config'] = dbh.scanConfigGet(id)
        ret['configdesc'] = dict()
        for key in list(ret['config'].keys()):
            if ':' not in key:
                ret['configdesc'][key] = self.config['__globaloptdescs__'][key]
            else:
                [modName, modOpt] = key.split(':')
                if modName not in list(self.config['__modules__'].keys()):
                    continue

                if modOpt not in list(self.config['__modules__'][modName]['optdescs'].keys()):
                    continue

                ret['configdesc'][key] = self.config['__modules__'][modName]['optdescs'][modOpt]

        meta = dbh.scanInstanceGet(id)
        if not meta:
            return json.dumps([])
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

    def rerunscan(self, id):
        # Snapshot the current configuration to be used by the scan
        cfg = deepcopy(self.config)
        modlist = list()
        sf = SpiderFoot(cfg)
        dbh = SpiderFootDb(cfg)
        info = dbh.scanInstanceGet(id)

        if not info:
            return self.error("Invalid scan ID.")

        scanconfig = dbh.scanConfigGet(id)
        scanname = info[0]
        scantarget = info[1]
        targetType = None

        if len(scanconfig) == 0:
            return self.error("Something went wrong internally.")

        modlist = scanconfig['_modulesenabled'].split(',')
        if "sfp__stor_stdout" in modlist:
            modlist.remove("sfp__stor_stdout")

        targetType = sf.targetType(scantarget)
        if targetType is None:
            # It must then be a name, as a re-run scan should always have a clean
            # target. Put quotes around the target value and try to determine the
            # target type again.
            targetType = sf.targetType(f'"{scantarget}"')

        if targetType != "HUMAN_NAME":
            scantarget = scantarget.lower()

        # Start running a new scan
        scanId = sf.genScanInstanceGUID()
        try:
            p = mp.Process(target=SpiderFootScanner, args=(scanname, scanId, scantarget, targetType, modlist, cfg))
            p.daemon = True
            p.start()
        except BaseException as e:
            print("[-] Scan [%s] failed: %s" % (scanId, e))
            return self.error("Scan [%s] failed: %s" % (scanId, e))

        # Wait until the scan has initialized
        while dbh.scanInstanceGet(scanId) == None:
            print("[info] Waiting for the scan to initialize...")
            time.sleep(1)

        raise cherrypy.HTTPRedirect(f"scaninfo?id={scanId}", status=302)

    rerunscan.exposed = True

    def rerunscanmulti(self, ids):
        # Snapshot the current configuration to be used by the scan
        cfg = deepcopy(self.config)
        modlist = list()
        sf = SpiderFoot(cfg)
        dbh = SpiderFootDb(cfg)

        for id in ids.split(","):
            info = dbh.scanInstanceGet(id)
            scanconfig = dbh.scanConfigGet(id)
            scanname = info[0]
            scantarget = info[1]
            targetType = None

            if len(scanconfig) == 0:
                return self.error("Something went wrong internally.")

            modlist = scanconfig['_modulesenabled'].split(',')
            if "sfp__stor_stdout" in modlist:
                modlist.remove("sfp__stor_stdout")

            targetType = sf.targetType(scantarget)
            if targetType == None:
                # Should never be triggered for a re-run scan..
                return self.error("Invalid target type. Could not recognize it as " + \
                                  "a human name, IP address, IP subnet, ASN, domain name or host name.")

            # Start running a new scan
            scanId = sf.genScanInstanceGUID()
            try:
                p = mp.Process(target=SpiderFootScanner, args=(scanname, scanId, scantarget, targetType, modlist, cfg))
                p.daemon = True
                p.start()
            except BaseException as e:
                print("[-] Scan [%s] failed: %s" % (scanId, e))
                return self.error("Scan [%s] failed: %s" % (scanId, e))

            # Wait until the scan has initialized
            while dbh.scanInstanceGet(scanId) == None:
                print("[info] Waiting for the scan to initialize...")
                time.sleep(1)

        templ = Template(filename='dyn/scanlist.tmpl', lookup=self.lookup)
        return templ.render(rerunscans=True, docroot=self.docroot, pageid="SCANLIST")

    rerunscanmulti.exposed = True


    # Configure a new scan
    def newscan(self):
        dbh = SpiderFootDb(self.config)
        types = dbh.eventTypes()
        templ = Template(filename='dyn/newscan.tmpl', lookup=self.lookup)
        return templ.render(pageid='NEWSCAN', types=types, docroot=self.docroot,
                            modules=self.config['__modules__'], scanname="",
                            selectedmods="", scantarget="")

    newscan.exposed = True


    # Clone an existing scan (pre-selected options in the newscan page)
    def clonescan(self, id):
        sf = SpiderFoot(self.config)
        dbh = SpiderFootDb(self.config)
        types = dbh.eventTypes()
        info = dbh.scanInstanceGet(id)

        if not info:
            return self.error("Invalid scan ID.")

        scanconfig = dbh.scanConfigGet(id)
        scanname = info[0]
        scantarget = info[1]
        targetType = None

        if scanname == "" or scantarget == "" or len(scanconfig) == 0:
            return self.error("Something went wrong internally.")

        targetType = sf.targetType(scantarget)
        if targetType == None:
            # It must be a name, so wrap quotes around it
            scantarget = "&quot;" + scantarget + "&quot;"

        modlist = scanconfig['_modulesenabled'].split(',')

        templ = Template(filename='dyn/newscan.tmpl', lookup=self.lookup)
        return templ.render(pageid='NEWSCAN', types=types, docroot=self.docroot,
                            modules=self.config['__modules__'], selectedmods=modlist,
                            scanname=str(scanname),
                            scantarget=str(scantarget))

    clonescan.exposed = True

    # Main page listing scans available
    def index(self):
        # Look for referenced templates in the current directory only
        templ = Template(filename='dyn/scanlist.tmpl', lookup=self.lookup)
        return templ.render(pageid='SCANLIST', docroot=self.docroot)

    index.exposed = True

    # Information about a selected scan
    def scaninfo(self, id):
        dbh = SpiderFootDb(self.config)
        res = dbh.scanInstanceGet(id)
        if res is None:
            return self.error("Scan ID not found.")

        templ = Template(filename='dyn/scaninfo.tmpl', lookup=self.lookup, input_encoding='utf-8')
        return templ.render(id=id, name=html.escape(res[0]), status=res[5], docroot=self.docroot,
                            pageid="SCANLIST")

    scaninfo.exposed = True

    # Settings
    def opts(self, updated=None):
        templ = Template(filename='dyn/opts.tmpl', lookup=self.lookup)
        self.token = random.SystemRandom().randint(0, 99999999)
        return templ.render(opts=self.config, pageid='SETTINGS', token=self.token, 
                            updated=updated, docroot=self.docroot)

    opts.exposed = True

    # Export configuration
    def optsexport(self, pattern):
        sf = SpiderFoot(self.config)
        conf = sf.configSerialize(self.config)
        content = ""
        for opt in sorted(conf):
            if ":_" in opt or opt.startswith("_"):
                continue
            if not pattern:
                content += opt + "=" + str(conf[opt]) + "\n"
            else:
                if pattern in opt:
                    content += opt + "=" + str(conf[opt]) + "\n"
        cherrypy.response.headers['Content-Disposition'] = 'attachment; filename="SpiderFoot.cfg"'
        cherrypy.response.headers['Content-Type'] = "text/plain"
        return content

    optsexport.exposed = True

    # Settings
    def optsraw(self):
        ret = dict()
        self.token = random.SystemRandom().randint(0, 99999999)
        for opt in self.config:
            if opt.startswith('__'):
                if opt == '__modules__':
                    for mod in sorted(self.config['__modules__'].keys()):
                        for mo in sorted(self.config['__modules__'][mod]['opts'].keys()):
                            if mo.startswith("_"):
                                continue
                            ret["module." + mod + "." + mo] = self.config['__modules__'][mod]['opts'][mo]
                continue
            ret["global." + opt] = self.config[opt]
        return json.dumps(['SUCCESS', {'token': self.token, 'data': ret}])

    optsraw.exposed = True

    # Generic error, but not exposed as not called directly
    def error(self, message):
        templ = Template(filename='dyn/error.tmpl', lookup=self.lookup)
        return templ.render(message=message, docroot=self.docroot)

    # Delete a scan
    def scandelete(self, id, confirm=None, raw=False):
        dbh = SpiderFootDb(self.config)
        res = dbh.scanInstanceGet(id)
        if res is None:
            if not raw:
                return self.error("Scan ID not found.")
            else:
                return json.dumps(["ERROR", "Scan ID not found."])

        if confirm is not None:
            dbh.scanInstanceDelete(id)
            if not raw:
                raise cherrypy.HTTPRedirect("/")
            else:
                return json.dumps(["SUCCESS", ""])
        else:
            templ = Template(filename='dyn/scandelete.tmpl', lookup=self.lookup)
            return templ.render(id=id, name=str(res[0]),
                                names=list(), ids=list(),
                                pageid="SCANLIST", docroot=self.docroot)

    scandelete.exposed = True

    # Delete a scan
    def scandeletemulti(self, ids, confirm=None):
        dbh = SpiderFootDb(self.config)
        names = list()

        for id in ids.split(','):
            res = dbh.scanInstanceGet(id)
            names.append(str(res[0]))
            if res is None:
                return self.error("Scan ID not found (" + id + ").")

            if res[5] in [ "RUNNING", "STARTING", "STARTED" ]:
                return self.error("You cannot delete running scans.")

        if confirm is not None:
            for id in ids.split(','):
                dbh.scanInstanceDelete(id)
            raise cherrypy.HTTPRedirect("/")
        else:
            templ = Template(filename='dyn/scandelete.tmpl', lookup=self.lookup)
            return templ.render(id=None, name=None, ids=ids.split(','), names=names,
                                pageid="SCANLIST", docroot=self.docroot)

    scandeletemulti.exposed = True

    # Save settings, also used to completely reset them to default
    def savesettings(self, allopts, token, configFile=None):
        if str(token) != str(self.token):
            return self.error("Invalid token (" + str(self.token) + ").")

        if configFile:  # configFile seems to get set even if a file isn't uploaded
            if configFile.file:
                contents = configFile.file.read()

                if type(contents) == bytes:
                    contents = contents.decode("utf-8")
                try:
                    tmp = dict()
                    for line in contents.split("\n"):
                        if "=" not in line:
                            continue
                        l = line.strip().split("=")
                        if len(l) == 1:
                            l[1] = ""
                        tmp[l[0]] = l[1]
                    allopts = json.dumps(tmp)
                except BaseException as e:
                    return self.error("Failed to parse input file. Was it generated from SpiderFoot? (" + str(e) + ")")

        try:
            dbh = SpiderFootDb(self.config)
            # Reset config to default
            if allopts == "RESET":
                dbh.configClear()  # Clear it in the DB
                self.config = deepcopy(self.defaultConfig)  # Clear in memory
            else:
                useropts = json.loads(allopts)
                cleanopts = dict()
                for opt in list(useropts.keys()):
                    cleanopts[opt] = self.cleanUserInput([useropts[opt]])[0]

                currentopts = deepcopy(self.config)

                # Make a new config where the user options override
                # the current system config.
                sf = SpiderFoot(self.config)
                self.config = sf.configUnserialize(cleanopts, currentopts)
                dbh.configSet(sf.configSerialize(self.config))
        except Exception as e:
            return self.error("Processing one or more of your inputs failed: " + str(e))

        raise cherrypy.HTTPRedirect("/opts?updated=1")

    savesettings.exposed = True

    # Save settings, also used to completely reset them to default
    def savesettingsraw(self, allopts, token):
        if str(token) != str(self.token):
            return json.dumps(["ERROR", "Invalid token (" + str(self.token) + ")."])

        try:
            dbh = SpiderFootDb(self.config)
            # Reset config to default
            if allopts == "RESET":
                dbh.configClear()  # Clear it in the DB
                self.config = deepcopy(self.defaultConfig)  # Clear in memory
            else:
                useropts = json.loads(allopts)
                cleanopts = dict()
                for opt in list(useropts.keys()):
                    cleanopts[opt] = self.cleanUserInput([useropts[opt]])[0]

                currentopts = deepcopy(self.config)

                # Make a new config where the user options override
                # the current system config.
                sf = SpiderFoot(self.config)
                self.config = sf.configUnserialize(cleanopts, currentopts)
                dbh.configSet(sf.configSerialize(self.config))
        except Exception as e:
            return json.dumps(["ERROR", "Processing one or more of your inputs failed: " + str(e)])

        return json.dumps(["SUCCESS", ""])

    savesettingsraw.exposed = True

    # Set a bunch of results (hashes) as false positive
    def resultsetfp(self, id, resultids, fp):
        dbh = SpiderFootDb(self.config)
        if fp not in ["0", "1"]:
            return json.dumps(["ERROR", "No FP flag set or not set correctly."])

        ids = json.loads(resultids)
        if not ids:
            return json.dumps(["ERROR", "No IDs supplied."])

        # Cannot set FPs if a scan is not completed
        status = dbh.scanInstanceGet(id)
        if not status:
            return self.error("Invalid scan ID: %s" % id)

        if status[5] not in [ "ABORTED", "FINISHED", "ERROR-FAILED" ]:
            return json.dumps(["WARNING", "Scan must be in a finished state when " + \
                               "setting False Positives."])

        # Make sure the user doesn't set something as non-FP when the
        # parent is set as an FP.
        if fp == "0":
            data = dbh.scanElementSourcesDirect(id, ids)
            for row in data:
                if str(row[14]) == "1":
                    return json.dumps(["WARNING",
                        "You cannot unset an element as False Positive " + \
                        "if a parent element is still False Positive."]);

        # Set all the children as FPs too.. it's only logical afterall, right?
        childs = dbh.scanElementChildrenAll(id, ids)
        allIds = ids + childs

        ret = dbh.scanResultsUpdateFP(id, allIds, fp)
        if not ret:
            return json.dumps(["ERROR", "Exception encountered."])
        else:
            return json.dumps(["SUCCESS", ""])

    resultsetfp.exposed = True

    # For the CLI to fetch a list of event types.
    def eventtypes(self):
        dbh = SpiderFootDb(self.config)
        types = dbh.eventTypes()
        ret = list()

        for r in types:
            ret.append([r[1], r[0]])

        ret = sorted(ret, key=itemgetter(0))

        return json.dumps(ret)

    eventtypes.exposed = True

    # For the CLI to fetch a list of modules.
    def modules(self):
        modinfo = list(self.config['__modules__'].keys())
        modinfo.sort()
        ret = list()
        for m in modinfo:
            if "__" in m:
                continue
            ret.append({'name': m, 'descr': self.config['__modules__'][m]['descr']})
        return json.dumps(ret)

    modules.exposed = True

    # For the CLI to test connectivity to this server.
    def ping(self):
        return json.dumps(["SUCCESS", self.config['__version__']])

    ping.exposed = True

    # For the CLI to run queries against the database.
    def query(self, query):
        data = None
        dbh = SpiderFootDb(self.config)

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        if not query:
            return json.dumps(["ERROR", "Invalid query."])

        if not query.lower().startswith("select"):
            return json.dumps(["ERROR", "Non-SELECTs are unpredictable and not recommended."])

        try:
            ret = dbh.dbh.execute(query)
            data = ret.fetchall()
            columnNames = [c[0] for c in dbh.dbh.description]
            data = [dict(zip(columnNames, row)) for row in data]
        except BaseException as e:
            return json.dumps(["ERROR", str(e)])

        return json.dumps(data)

    query.exposed = True

    # Initiate a scan
    def startscan(self, scanname, scantarget, modulelist, typelist, usecase, cli=None):
        #Swap the globalscantable for the database handler
        dbh = SpiderFootDb(self.config)

        # Snapshot the current configuration to be used by the scan
        cfg = deepcopy(self.config)
        modlist = list()
        sf = SpiderFoot(cfg)
        targetType = None
        [scanname, scantarget] = self.cleanUserInput([scanname, scantarget])

        if scanname == "" or scantarget == "":
            if cli:
                return json.dumps(["ERROR", "Incorrect usage: scan name or target was not specified."])
            else:
                return self.error("Invalid request: scan name or target was not specified.")

        if typelist == "" and modulelist == "" and usecase == "":
            if cli:
                return json.dumps(["ERROR", "Incorrect usage: no modules specified for scan."])
            else:
                return self.error("Invalid request: no modules specified for scan.")


        # User selected modules
        if modulelist != "":
            modlist = modulelist.replace('module_', '').split(',')

        # User selected types
        if len(modlist) == 0 and typelist != "":
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

        # User selected a use case
        if len(modlist) == 0 and usecase != "":
            for mod in self.config['__modules__']:
                if usecase == 'all' or usecase in self.config['__modules__'][mod]['cats']:
                    modlist.append(mod)

        # Add our mandatory storage module..
        if "sfp__stor_db" not in modlist:
            modlist.append("sfp__stor_db")
        modlist.sort()

        targetType = sf.targetType(scantarget)
        if targetType is None:
            if not cli:
                return self.error("Invalid target type. Could not recognize it as " + \
                                  "a human name, IP address, IP subnet, ASN, domain " + \
                                   "name or host name.")
            else:
                return json.dumps(["ERROR", "Unrecognised target type."])

        # Delete the stdout module in case it crept in
        if "sfp__stor_stdout" in modlist:
            modlist.remove("sfp__stor_stdout")

        # Start running a new scan
        if targetType in [ "HUMAN_NAME", "USERNAME" ]:
            scantarget = scantarget.replace("\"", "")
        else:
            scantarget = scantarget.lower()

        # Start running a new scan
        scanId = sf.genScanInstanceGUID()
        try:
            p = mp.Process(target=SpiderFootScanner, args=(scanname, scanId, scantarget, targetType, modlist, cfg))
            p.daemon = True
            p.start()
        except BaseException as e:
            print("[-] Scan [%s] failed: %s" % (scanId, e))
            return self.error("Scan [%s] failed: %s" % (scanId, e))

        # Wait until the scan has initialized
        # Check the database for the scan status results
        while dbh.scanInstanceGet(scanId) is None:
            print("[info] Waiting for the scan to initialize...")
            time.sleep(1)

        if not cli:
            raise cherrypy.HTTPRedirect(f"/scaninfo?id={scanId}")
        else:
            return json.dumps(["SUCCESS", scanId])

    startscan.exposed = True


    # Stop a scan (id variable is unnecessary for now given that only one simultaneous
    # scan is permitted.)
    def stopscanmulti(self, ids):
        dbh = SpiderFootDb(self.config)
        error = list()

        for id in ids.split(","):
            errState = False
            scaninfo = dbh.scanInstanceGet(id)
            if not scaninfo:
                return self.error("Invalid scan ID: %s" % id)

            scanname = str(scaninfo[0])
            scanstatus = scaninfo[5]
            if scanstatus == "FINISHED":
                error.append("Scan '" + scanname + "' is in a finished state. <a href='/scandelete?id=" + \
                             id + "&confirm=1'>Maybe you want to delete it instead?</a>")
                errState = True

            if not errState and scanstatus == "ABORTED":
                error.append("Scan '" + scanname + "' is already aborted.")
                errState = True

            if not errState:
                #set the scanstatus in the db to "ABORT-REQUESTED"
                dbh.scanInstanceSet(id, status="ABORT-REQUESTED")

        raise cherrypy.HTTPRedirect("/")

    stopscanmulti.exposed = True


    # Stop a scan.
    def stopscan(self, id, cli=None):
        dbh = SpiderFootDb(self.config)
        scaninfo = dbh.scanInstanceGet(id)

        if not scaninfo:
            if not cli:
                return self.error("Invalid scan ID.")
            else:
                return json.dumps(["ERROR", "Invalid scan ID."])

        scanstatus = scaninfo[5]
        print(scanstatus)

        if scanstatus == "ABORTED":
            if not cli:
                return self.error("The scan is already aborted.")
            else:
                return json.dumps(["ERROR", "Scan already aborted."])

        if not scanstatus == "RUNNING":
            if not cli:
                return self.error("The running scan is currently in the state '" + \
                                  scanstatus + "', please try again later or restart " + \
                                  " SpiderFoot.")
            else:
                return json.dumps(["ERROR", "Scan in an invalid state for stopping."])

        dbh.scanInstanceSet(id, status="ABORT-REQUESTED")
        if not cli:
            raise cherrypy.HTTPRedirect("/")
        else:
            return json.dumps(["SUCCESS", ""])

    stopscan.exposed = True

    #
    # DATA PROVIDERS
    #

    # Scan log data
    def scanlog(self, id, limit=None, rowId=None, reverse=None):
        dbh = SpiderFootDb(self.config)
        retdata = []

        try:
            data = dbh.scanLogs(id, limit, rowId, reverse)
        except:
            return json.dumps(retdata)

        for row in data:
            generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0] / 1000))
            retdata.append([generated, row[1], row[2], html.escape(row[3]), row[4]])
        return json.dumps(retdata)

    scanlog.exposed = True

    # Scan error data
    def scanerrors(self, id, limit=None):
        dbh = SpiderFootDb(self.config)
        retdata = []

        try:
            data = dbh.scanErrors(id, limit)
        except:
            return json.dumps(retdata)

        for row in data:
            generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0] / 1000))
            retdata.append([generated, row[1],
                            html.escape(str(row[2]))])
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

        if not data:
            return json.dumps([])

        created = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data[2]))
        started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data[3]))
        ended = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data[4]))

        retdata = [data[0], data[1], created, started, ended, data[5]]
        return json.dumps(retdata)

    scanstatus.exposed = True

    # Summary of scan results
    def scansummary(self, id, by):
        retdata = []

        dbh = SpiderFootDb(self.config)

        try:
            scandata = dbh.scanResultSummary(id, by)
        except:
            return json.dumps(retdata)

        try:
            statusdata = dbh.scanInstanceGet(id)
        except:
            return json.dumps(retdata)

        for row in scandata:
            if row[0] == "ROOT":
                continue
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[2]))
            retdata.append([row[0], row[1], lastseen, row[3], row[4], statusdata[5]])
        return json.dumps(retdata)

    scansummary.exposed = True

    # Event results for a scan
    def scaneventresults(self, id, eventType, filterfp=False):
        retdata = []

        dbh = SpiderFootDb(self.config)

        try:
            data = dbh.scanResultEvent(id, eventType, filterfp)
        except:
            return json.dumps(retdata)

        for row in data:
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
            escapeddata = html.escape(row[1])
            escapedsrc = html.escape(row[2])
            retdata.append([lastseen, escapeddata, escapedsrc,
                            row[3], row[5], row[6], row[7], row[8],
                            row[13], row[14], row[4]])
        return json.dumps(retdata, ensure_ascii=False)

    scaneventresults.exposed = True

    # Unique event results for a scan
    def scaneventresultsunique(self, id, eventType, filterfp=False):
        dbh = SpiderFootDb(self.config)
        retdata = []

        try:
            data = dbh.scanResultEventUnique(id, eventType, filterfp)
        except:
            return json.dumps(retdata)

        for row in data:
            escaped = html.escape(row[0])
            retdata.append([escaped, row[1], row[2]])
        return json.dumps(retdata, ensure_ascii=False)

    scaneventresultsunique.exposed = True

    # Search
    def search(self, id=None, eventType=None, value=None):
        try:
            data = self.searchBase(id, eventType, value)
        except:
            return json.dumps([])

        return json.dumps(data, ensure_ascii=False)

    search.exposed = True

    # Historical data for the scan, graphs will be rendered in JS
    def scanhistory(self, id):
        dbh = SpiderFootDb(self.config)

        try:
            data = dbh.scanResultHistory(id)
        except:
            return json.dumps([])

        return json.dumps(data, ensure_ascii=False)

    scanhistory.exposed = True

    def scanelementtypediscovery(self, id, eventType):
        sf = SpiderFoot(self.config)
        dbh = SpiderFootDb(self.config)
        pc = dict()
        datamap = dict()

        # Get the events we will be tracing back from
        leafSet = dbh.scanResultEvent(id, eventType)
        [datamap, pc] = dbh.scanElementSourcesAll(id, leafSet)

        # Delete the ROOT key as it adds no value from a viz perspective
        del pc['ROOT']
        retdata = dict()
        retdata['tree'] = sf.dataParentChildToTree(pc)
        retdata['data'] = datamap

        return json.dumps(retdata, ensure_ascii=False)

    scanelementtypediscovery.exposed = True
