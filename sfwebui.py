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
import csv
import html
import json
import logging
import multiprocessing as mp
import random
import time
from copy import deepcopy
from io import StringIO
from operator import itemgetter

import cherrypy
from cherrypy import _cperror
from mako.lookup import TemplateLookup
from mako.template import Template
from secure import SecureHeaders

from spiderfoot import SpiderFootDb
from sflib import SpiderFoot
from sfscan import SpiderFootScanner

mp.set_start_method("spawn", force=True)


class SpiderFootWebUi:
    lookup = TemplateLookup(directories=[''])
    defaultConfig = dict()
    config = dict()
    token = None
    docroot = ''
    log = logging.getLogger(__name__)

    def __init__(self, web_config, config):
        """Initialize web server

        Args:
            web_config: config settings for web interface (interface, port, root path)
            config: SpiderFoot config

        Raises:
            TypeError: arg type is invalid
            ValueError: arg value is invalid
        """

        if not isinstance(config, dict):
            raise TypeError(f"config is {type(config)}; expected dict()")
        if not config:
            raise ValueError("config is empty")

        if not isinstance(web_config, dict):
            raise TypeError(f"web_config is {type(web_config)}; expected dict()")
        if not config:
            raise ValueError("web_config is empty")

        self.docroot = web_config.get('root', '/').rstrip('/')

        # 'config' supplied will be the defaults, let's supplement them
        # now with any configuration which may have previously been saved.
        self.defaultConfig = deepcopy(config)
        dbh = SpiderFootDb(self.defaultConfig)
        sf = SpiderFoot(self.defaultConfig)
        self.config = sf.configUnserialize(dbh.configGet(), self.defaultConfig)

        cherrypy.config.update({
            'error_page.401': self.error_page_401,
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

    def error_page(self):
        """Error page"""

        cherrypy.response.status = 500

        if self.config['_debug']:
            cherrypy.response.body = _cperror.get_error_page(status=500, traceback=_cperror.format_exc())
        else:
            cherrypy.response.body = b"<html><body>Error</body></html>"

    def error_page_401(self, status, message, traceback, version):
        """Unauthorized eError page 401

        Args:
            status: TBD
            message: TBD
            traceback: TBD
            version: TBD

        Returns:
            str: HTML response
        """
        return b""

    def error_page_404(self, status, message, traceback, version):
        """Error page 404

        Args:
            status: TBD
            message: TBD
            traceback: TBD
            version: TBD

        Returns:
            str: HTTP response template
        """

        templ = Template(filename='dyn/error.tmpl', lookup=self.lookup)
        return templ.render(message='Not Found', docroot=self.docroot, status=status)

    def cleanUserInput(self, inputList):
        """Sanitize user input, poorly.

        Args:
            inputList (list): TBD

        Returns:
            list: sanitized input

        Raises:
            TypeError: inputList type was invalid
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
        if [id, eventType, value].count('') == 3 or [id, eventType, value].count(None) == 3:
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
        except Exception:
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
        return fileobj.getvalue().encode('utf-8')

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
        return fileobj.getvalue().encode('utf-8')

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
        return fileobj.getvalue().encode('utf-8')

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
        return json.dumps(scaninfo).encode('utf-8')

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

    def scanopts(self, id):
        """Configuration used for a scan

        Args:
            id: scan ID

        Returns:
            str: options as JSON string
        """

        ret = dict()
        dbh = SpiderFootDb(self.config)
        ret['config'] = dbh.scanConfigGet(id)
        ret['configdesc'] = dict()
        for key in list(ret['config'].keys()):
            if ':' not in key:
                ret['configdesc'][key] = self.config['__globaloptdescs__'].get(key, f"{key} (legacy)")
            else:
                [modName, modOpt] = key.split(':')
                if modName not in list(self.config['__modules__'].keys()):
                    continue

                if modOpt not in list(self.config['__modules__'][modName]['optdescs'].keys()):
                    continue

                ret['configdesc'][key] = self.config['__modules__'][modName]['optdescs'][modOpt]

        meta = dbh.scanInstanceGet(id)
        if not meta:
            return json.dumps([]).encode('utf-8')
        if meta[3] != 0:
            started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(meta[3]))
        else:
            started = "Not yet"

        if meta[4] != 0:
            finished = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(meta[4]))
        else:
            finished = "Not yet"
        ret['meta'] = [meta[0], meta[1], meta[2], started, finished, meta[5]]

        return json.dumps(ret).encode('utf-8')

    scanopts.exposed = True

    def rerunscan(self, id):
        """Rerun a scan

        Args:
            id (str): scan ID

        Returns:
            None

        Raises:
            HTTPRedirect: redirect to info page for new scan
        """

        # Snapshot the current configuration to be used by the scan
        cfg = deepcopy(self.config)
        modlist = list()
        sf = SpiderFoot(cfg)
        dbh = SpiderFootDb(cfg)
        info = dbh.scanInstanceGet(id)

        if not info:
            return self.error("Invalid scan ID.")

        scanname = info[0]
        scantarget = info[1]

        scanconfig = dbh.scanConfigGet(id)
        if not scanconfig:
            return self.error(f"Error loading config from scan: {id}")

        modlist = scanconfig['_modulesenabled'].split(',')
        if "sfp__stor_stdout" in modlist:
            modlist.remove("sfp__stor_stdout")

        targetType = sf.targetType(scantarget)
        if not targetType:
            # It must then be a name, as a re-run scan should always have a clean
            # target. Put quotes around the target value and try to determine the
            # target type again.
            targetType = sf.targetType(f'"{scantarget}"')

        if targetType not in ["HUMAN_NAME", "BITCOIN_ADDRESS"]:
            scantarget = scantarget.lower()

        # Start running a new scan
        scanId = sf.genScanInstanceId()
        try:
            p = mp.Process(target=SpiderFootScanner, args=(scanname, scanId, scantarget, targetType, modlist, cfg))
            p.daemon = True
            p.start()
        except Exception as e:
            self.log.error(f"[-] Scan [{scanId}] failed: {e}")
            return self.error(f"[-] Scan [{scanId}] failed: {e}")

        # Wait until the scan has initialized
        while dbh.scanInstanceGet(scanId) is None:
            self.log.info("Waiting for the scan to initialize...")
            time.sleep(1)

        raise cherrypy.HTTPRedirect(f"{self.docroot}/scaninfo?id={scanId}", status=302)

    rerunscan.exposed = True

    def rerunscanmulti(self, ids):
        """Rerun scans

        Args:
            ids (str): comma separated list of scan IDs

        Returns:
            None
        """

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
            if targetType is None:
                # Should never be triggered for a re-run scan..
                return self.error("Invalid target type. Could not recognize it as a target SpiderFoot supports.")

            # Start running a new scan
            scanId = sf.genScanInstanceId()
            try:
                p = mp.Process(target=SpiderFootScanner, args=(scanname, scanId, scantarget, targetType, modlist, cfg))
                p.daemon = True
                p.start()
            except Exception as e:
                self.log.error(f"[-] Scan [{scanId}] failed: {e}")
                return self.error(f"[-] Scan [{scanId}] failed: {e}")

            # Wait until the scan has initialized
            while dbh.scanInstanceGet(scanId) is None:
                self.log.info("Waiting for the scan to initialize...")
                time.sleep(1)

        templ = Template(filename='dyn/scanlist.tmpl', lookup=self.lookup)
        return templ.render(rerunscans=True, docroot=self.docroot, pageid="SCANLIST")

    rerunscanmulti.exposed = True

    def newscan(self):
        """Configure a new scan

        Returns:
            None
        """

        dbh = SpiderFootDb(self.config)
        types = dbh.eventTypes()
        templ = Template(filename='dyn/newscan.tmpl', lookup=self.lookup)
        return templ.render(pageid='NEWSCAN', types=types, docroot=self.docroot,
                            modules=self.config['__modules__'], scanname="",
                            selectedmods="", scantarget="")

    newscan.exposed = True

    def clonescan(self, id):
        """
        Clone an existing scan (pre-selected options in the newscan page)

        Args:
            id (str): scan ID to clone

        Returns:
            None
        """

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
        if targetType is None:
            # It must be a name, so wrap quotes around it
            scantarget = "&quot;" + scantarget + "&quot;"

        modlist = scanconfig['_modulesenabled'].split(',')

        templ = Template(filename='dyn/newscan.tmpl', lookup=self.lookup)
        return templ.render(pageid='NEWSCAN', types=types, docroot=self.docroot,
                            modules=self.config['__modules__'], selectedmods=modlist,
                            scanname=str(scanname),
                            scantarget=str(scantarget))

    clonescan.exposed = True

    def index(self):
        """Main page listing scans available

        Returns:
            None
        """

        templ = Template(filename='dyn/scanlist.tmpl', lookup=self.lookup)
        return templ.render(pageid='SCANLIST', docroot=self.docroot)

    index.exposed = True

    def scaninfo(self, id):
        """Information about a selected scan

        Args:
            id (str): scan id

        Returns:
            None
        """

        dbh = SpiderFootDb(self.config)
        res = dbh.scanInstanceGet(id)
        if res is None:
            return self.error("Scan ID not found.")

        templ = Template(filename='dyn/scaninfo.tmpl', lookup=self.lookup, input_encoding='utf-8')
        return templ.render(id=id, name=html.escape(res[0]), status=res[5], docroot=self.docroot,
                            pageid="SCANLIST")

    scaninfo.exposed = True

    def opts(self, updated=None):
        """Settings

        Args:
            updated: TBD

        Returns:
            None
        """

        templ = Template(filename='dyn/opts.tmpl', lookup=self.lookup)
        self.token = random.SystemRandom().randint(0, 99999999)
        return templ.render(opts=self.config, pageid='SETTINGS', token=self.token,
                            updated=updated, docroot=self.docroot)

    opts.exposed = True

    def optsexport(self, pattern):
        """Export configuration

        Args:
            pattern: TBD

        Returns:
            None
        """

        sf = SpiderFoot(self.config)
        conf = sf.configSerialize(self.config)
        content = ""

        for opt in sorted(conf):
            if ":_" in opt or opt.startswith("_"):
                continue

            if pattern:
                if pattern in opt:
                    content += "%s=%s\n" % (opt, conf[opt])
            else:
                content += "%s=%s\n" % (opt, conf[opt])

        cherrypy.response.headers['Content-Disposition'] = 'attachment; filename="SpiderFoot.cfg"'
        cherrypy.response.headers['Content-Type'] = "text/plain"
        return content

    optsexport.exposed = True

    def optsraw(self):
        """Settings

        Returns:
            str: settings as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        ret = dict()
        self.token = random.SystemRandom().randint(0, 99999999)
        for opt in self.config:
            if not opt.startswith('__'):
                ret["global." + opt] = self.config[opt]
                continue

            if opt == '__modules__':
                for mod in sorted(self.config['__modules__'].keys()):
                    for mo in sorted(self.config['__modules__'][mod]['opts'].keys()):
                        if mo.startswith("_"):
                            continue
                        ret["module." + mod + "." + mo] = self.config['__modules__'][mod]['opts'][mo]

        return json.dumps(['SUCCESS', {'token': self.token, 'data': ret}]).encode('utf-8')

    optsraw.exposed = True

    def error(self, message):
        """Generic error, but not exposed as not called directly

        Args:
            message (str): error message

        Returns:
            None
        """

        templ = Template(filename='dyn/error.tmpl', lookup=self.lookup)
        return templ.render(message=message, docroot=self.docroot)

    def scandelete(self, id, confirm=None):
        """Delete a scan

        Args:
            id (str): scan ID
            confirm (str): specify any value (except None) to confirm deletion of the scan

        Returns:
            None

        Raises:
            HTTPRedirect: redirect to scan list page
        """

        dbh = SpiderFootDb(self.config)
        res = dbh.scanInstanceGet(id)

        if res is None:
            if cherrypy.request.headers and 'application/json' in cherrypy.request.headers.get('Accept'):
                cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"
                return json.dumps(["ERROR", "Scan ID not found."]).encode('utf-8')

            return self.error("Scan ID not found.")

        if confirm:
            dbh.scanInstanceDelete(id)

            if cherrypy.request.headers and 'application/json' in cherrypy.request.headers.get('Accept'):
                cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"
                return json.dumps(["SUCCESS", ""]).encode('utf-8')

            raise cherrypy.HTTPRedirect(f"{self.docroot}/")

        templ = Template(filename='dyn/scandelete.tmpl', lookup=self.lookup)
        return templ.render(id=id, name=str(res[0]),
                            names=list(), ids=list(),
                            pageid="SCANLIST", docroot=self.docroot)

    scandelete.exposed = True

    def scandeletemulti(self, ids, confirm=None):
        """Delete a scan

        Args:
            ids (str): comma separated list of scan IDs
            confirm: TBD

        Returns:
            None

        Raises:
            HTTPRedirect: redirect to scan list page
        """

        dbh = SpiderFootDb(self.config)
        names = list()

        for id in ids.split(','):
            res = dbh.scanInstanceGet(id)
            if not res:
                continue
            names.append(str(res[0]))
            if res is None:
                return self.error("Scan ID not found (" + id + ").")

            if res[5] in ["RUNNING", "STARTING", "STARTED"]:
                return self.error("You cannot delete running scans.")

        if confirm:
            for id in ids.split(','):
                dbh.scanInstanceDelete(id)
            raise cherrypy.HTTPRedirect(f"{self.docroot}/")

        templ = Template(filename='dyn/scandelete.tmpl', lookup=self.lookup)
        return templ.render(id=None, name=None, ids=ids.split(','), names=names,
                            pageid="SCANLIST", docroot=self.docroot)

    scandeletemulti.exposed = True

    def savesettings(self, allopts, token, configFile=None):
        """Save settings, also used to completely reset them to default

        Args:
            allopts: TBD
            token: CSRF token
            configFile: TBD

        Returns:
            None

        Raises:
            HTTPRedirect: redirect to scan settings
        """

        if str(token) != str(self.token):
            return self.error("Invalid token (%s)" % self.token)

        if configFile:  # configFile seems to get set even if a file isn't uploaded
            if configFile.file:
                contents = configFile.file.read()

                if type(contents) == bytes:
                    contents = contents.decode('utf-8')

                try:
                    tmp = dict()
                    for line in contents.split("\n"):
                        if "=" not in line:
                            continue

                        opt_array = line.strip().split("=")
                        if len(opt_array) == 1:
                            opt_array[1] = ""

                        tmp[opt_array[0]] = '='.join(opt_array[1:])

                    allopts = json.dumps(tmp).encode('utf-8')
                except Exception as e:
                    return self.error("Failed to parse input file. Was it generated from SpiderFoot? (%s)" % e)

        # Reset config to default
        if allopts == "RESET":
            if self.reset_settings():
                raise cherrypy.HTTPRedirect(f"{self.docroot}/opts?updated=1")
            else:
                return self.error("Failed to reset settings")

        # Save settings
        try:
            dbh = SpiderFootDb(self.config)
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
            return self.error("Processing one or more of your inputs failed: %s" % e)

        raise cherrypy.HTTPRedirect(f"{self.docroot}/opts?updated=1")

    savesettings.exposed = True

    def savesettingsraw(self, allopts, token):
        """Save settings, also used to completely reset them to default

        Args:
            allopts: TBD
            token: CSRF token

        Returns:
            str: save success as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        if str(token) != str(self.token):
            return json.dumps(["ERROR", "Invalid token (%s)." % self.token]).encode('utf-8')

        # Reset config to default
        if allopts == "RESET":
            if self.reset_settings():
                return json.dumps(["SUCCESS", ""]).encode('utf-8')
            else:
                return json.dumps(["ERROR", "Failed to reset settings"]).encode('utf-8')

        # Save settings
        try:
            dbh = SpiderFootDb(self.config)
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
            return json.dumps(["ERROR", "Processing one or more of your inputs failed: %s" % e]).encode('utf-8')

        return json.dumps(["SUCCESS", ""]).encode('utf-8')

    savesettingsraw.exposed = True

    def reset_settings(self):
        """Reset settings to default.

        Returns:
            bool: success
        """

        try:
            dbh = SpiderFootDb(self.config)
            dbh.configClear()  # Clear it in the DB
            self.config = deepcopy(self.defaultConfig)  # Clear in memory
        except Exception:
            return False

        return True

    def resultsetfp(self, id, resultids, fp):
        """Set a bunch of results (hashes) as false positive

        Args:
            id (str): scan ID
            resultids (str): comma separated list of result IDs
            fp (str): 0 or 1

        Returns:
            str: set false positive status as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        dbh = SpiderFootDb(self.config)

        if fp not in ["0", "1"]:
            return json.dumps(["ERROR", "No FP flag set or not set correctly."]).encode('utf-8')

        ids = json.loads(resultids)
        if not ids:
            return json.dumps(["ERROR", "No IDs supplied."]).encode('utf-8')

        # Cannot set FPs if a scan is not completed
        status = dbh.scanInstanceGet(id)
        if not status:
            return self.error("Invalid scan ID: %s" % id)

        if status[5] not in ["ABORTED", "FINISHED", "ERROR-FAILED"]:
            return json.dumps(["WARNING", "Scan must be in a finished state when setting False Positives."]).encode('utf-8')

        # Make sure the user doesn't set something as non-FP when the
        # parent is set as an FP.
        if fp == "0":
            data = dbh.scanElementSourcesDirect(id, ids)
            for row in data:
                if str(row[14]) == "1":
                    return json.dumps([
                        "WARNING",
                        "Cannot unset element %s as False Positive if a parent element is still False Positive." % id
                    ]).encode('utf-8')

        # Set all the children as FPs too.. it's only logical afterall, right?
        childs = dbh.scanElementChildrenAll(id, ids)
        allIds = ids + childs

        ret = dbh.scanResultsUpdateFP(id, allIds, fp)
        if ret:
            return json.dumps(["SUCCESS", ""]).encode('utf-8')

        return json.dumps(["ERROR", "Exception encountered."]).encode('utf-8')

    resultsetfp.exposed = True

    def eventtypes(self):
        """For the CLI to fetch a list of event types.

        Returns:
            str: list of event types
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        dbh = SpiderFootDb(self.config)
        types = dbh.eventTypes()
        ret = list()

        for r in types:
            ret.append([r[1], r[0]])

        ret = sorted(ret, key=itemgetter(0))

        return json.dumps(ret).encode('utf-8')

    eventtypes.exposed = True

    def modules(self):
        """For the CLI to fetch a list of modules.

        Returns:
            str: list of modules
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        modinfo = list(self.config['__modules__'].keys())
        modinfo.sort()
        ret = list()
        for m in modinfo:
            if "__" in m:
                continue
            ret.append({'name': m, 'descr': self.config['__modules__'][m]['descr']})

        return json.dumps(ret).encode('utf-8')

    modules.exposed = True

    def ping(self):
        """For the CLI to test connectivity to this server.

        Returns:
            str: SpiderFoot version as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        return json.dumps(["SUCCESS", self.config['__version__']]).encode('utf-8')

    ping.exposed = True

    def query(self, query):
        """For the CLI to run queries against the database.

        Args:
            query (str): SQL query

        Returns:
            str: query results as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        data = None
        dbh = SpiderFootDb(self.config)

        if not query:
            return json.dumps(["ERROR", "Invalid query."]).encode('utf-8')

        if not query.lower().startswith("select"):
            return json.dumps(["ERROR", "Non-SELECTs are unpredictable and not recommended."]).encode('utf-8')

        try:
            ret = dbh.dbh.execute(query)
            data = ret.fetchall()
            columnNames = [c[0] for c in dbh.dbh.description]
            data = [dict(zip(columnNames, row)) for row in data]
        except Exception as e:
            return json.dumps(["ERROR", str(e)]).encode('utf-8')

        return json.dumps(data).encode('utf-8')

    query.exposed = True

    def startscan(self, scanname, scantarget, modulelist, typelist, usecase):
        """Initiate a scan

        Args:
            scanname (str): scan name
            scantarget (str): scan target
            modulelist (str): TBD
            typelist (str): TBD
            usecase (str): module group (passive, investigate, footprint, all)

        Returns:
            str: start scan status as JSON

        Raises:
            HTTPRedirect: redirect to new scan info page
        """

        # Swap the globalscantable for the database handler
        dbh = SpiderFootDb(self.config)

        # Snapshot the current configuration to be used by the scan
        cfg = deepcopy(self.config)
        modlist = list()
        sf = SpiderFoot(cfg)
        targetType = None
        [scanname, scantarget] = self.cleanUserInput([scanname, scantarget])

        if scanname == "" or scantarget == "":
            if cherrypy.request.headers and 'application/json' in cherrypy.request.headers.get('Accept'):
                cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"
                return json.dumps(["ERROR", "Incorrect usage: scan name or target was not specified."]).encode('utf-8')

            return self.error("Invalid request: scan name or target was not specified.")

        if typelist == "" and modulelist == "" and usecase == "":
            if cherrypy.request.headers and 'application/json' in cherrypy.request.headers.get('Accept'):
                cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"
                return json.dumps(["ERROR", "Incorrect usage: no modules specified for scan."]).encode('utf-8')

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
                if usecase == 'all' or usecase in self.config['__modules__'][mod]['group']:
                    modlist.append(mod)

        # Add our mandatory storage module..
        if "sfp__stor_db" not in modlist:
            modlist.append("sfp__stor_db")
        modlist.sort()

        targetType = sf.targetType(scantarget)
        if targetType is None:
            if cherrypy.request.headers and 'application/json' in cherrypy.request.headers.get('Accept'):
                cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"
                return json.dumps(["ERROR", "Unrecognised target type."]).encode('utf-8')

            return self.error("Invalid target type. Could not recognize it as a target SpiderFoot supports.")

        # Delete the stdout module in case it crept in
        if "sfp__stor_stdout" in modlist:
            modlist.remove("sfp__stor_stdout")

        # Start running a new scan
        if targetType in ["HUMAN_NAME", "USERNAME", "BITCOIN_ADDRESS"]:
            scantarget = scantarget.replace("\"", "")
        else:
            scantarget = scantarget.lower()

        # Start running a new scan
        scanId = sf.genScanInstanceId()
        try:
            p = mp.Process(target=SpiderFootScanner, args=(scanname, scanId, scantarget, targetType, modlist, cfg))
            p.daemon = True
            p.start()
        except Exception as e:
            self.log.error(f"[-] Scan [{scanId}] failed: {e}")
            return self.error(f"[-] Scan [{scanId}] failed: {e}")

        # Wait until the scan has initialized
        # Check the database for the scan status results
        while dbh.scanInstanceGet(scanId) is None:
            self.log.info("Waiting for the scan to initialize...")
            time.sleep(1)

        if cherrypy.request.headers and 'application/json' in cherrypy.request.headers.get('Accept'):
            cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"
            return json.dumps(["SUCCESS", scanId]).encode('utf-8')

        raise cherrypy.HTTPRedirect(f"{self.docroot}/scaninfo?id={scanId}")

    startscan.exposed = True

    def stopscanmulti(self, ids):
        """Stop a scan

        Args:
            ids (str): comma separated list of scan IDs

        Note:
            Unnecessary for now given that only one simultaneous scan is permitted

        Returns:
            str: stop scan status as JSON

        Raises:
            HTTPRedirect: redirect to home page
        """

        dbh = SpiderFootDb(self.config)
        error = list()

        for id in ids.split(","):
            scaninfo = dbh.scanInstanceGet(id)

            if not scaninfo:
                return self.error("Invalid scan ID: %s" % id)

            scanname = str(scaninfo[0])
            scanstatus = scaninfo[5]

            if scanstatus == "FINISHED":
                error.append("Scan '%s' is in a finished state. <a href='/scandelete?id=%s&confirm=1'>Maybe you want to delete it instead?</a>" % (scanname, id))
                continue

            if scanstatus == "ABORTED":
                error.append("Scan '" + scanname + "' is already aborted.")
                continue

            dbh.scanInstanceSet(id, status="ABORT-REQUESTED")

        raise cherrypy.HTTPRedirect(f"{self.docroot}/")

    stopscanmulti.exposed = True

    def stopscan(self, id):
        """Stop a scan.

        Args:
            id (str): scan ID

        Returns:
            str: stop scan status as JSON

        Raises:
            HTTPRedirect: redirect to home page
        """

        dbh = SpiderFootDb(self.config)
        scaninfo = dbh.scanInstanceGet(id)

        if not scaninfo:
            if cherrypy.request.headers and 'application/json' in cherrypy.request.headers.get('Accept'):
                cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"
                return json.dumps(["ERROR", "Invalid scan ID."]).encode('utf-8')

            return self.error("Invalid scan ID.")

        scanstatus = scaninfo[5]

        if scanstatus == "ABORTED":
            if cherrypy.request.headers and 'application/json' in cherrypy.request.headers.get('Accept'):
                cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"
                return json.dumps(["ERROR", "Scan already aborted."]).encode('utf-8')

            return self.error("The scan is already aborted.")

        if not scanstatus == "RUNNING":
            if cherrypy.request.headers and 'application/json' in cherrypy.request.headers.get('Accept'):
                cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"
                return json.dumps(["ERROR", "Scan in an invalid state for stopping."]).encode('utf-8')

            return self.error("The running scan is currently in the state '%s', please try again later or restart SpiderFoot." % scanstatus)

        dbh.scanInstanceSet(id, status="ABORT-REQUESTED")

        if 'application/json' in cherrypy.request.headers.get('Accept'):
            cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"
            return json.dumps(["SUCCESS", ""]).encode('utf-8')

        raise cherrypy.HTTPRedirect(f"{self.docroot}/")

    stopscan.exposed = True

    #
    # DATA PROVIDERS
    #

    def scanlog(self, id, limit=None, rowId=None, reverse=None):
        """Scan log data

        Args:
            id: TBD
            limit: TBD
            rowId: TBD
            reverse: TBD

        Returns:
            str: JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        dbh = SpiderFootDb(self.config)
        retdata = []

        try:
            data = dbh.scanLogs(id, limit, rowId, reverse)
        except Exception:
            return json.dumps(retdata).encode('utf-8')

        for row in data:
            generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0] / 1000))
            retdata.append([generated, row[1], row[2], html.escape(row[3]), row[4]])

        return json.dumps(retdata).encode('utf-8')

    scanlog.exposed = True

    def scanerrors(self, id, limit=None):
        """Scan error data

        Args:
            id (str): scan ID
            limit: TBD

        Returns:
            str: scan errors as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        dbh = SpiderFootDb(self.config)
        retdata = []

        try:
            data = dbh.scanErrors(id, limit)
        except Exception:
            return json.dumps(retdata).encode('utf-8')

        for row in data:
            generated = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0] / 1000))
            retdata.append([generated, row[1], html.escape(str(row[2]))])

        return json.dumps(retdata).encode('utf-8')

    scanerrors.exposed = True

    def scanlist(self):
        """Produce a list of scans.

        Returns:
            str: scan list as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        dbh = SpiderFootDb(self.config)
        data = dbh.scanInstanceList()
        retdata = []
        for row in data:
            created = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[3]))

            if row[4] == 0:
                started = "Not yet"
            else:
                started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[4]))

            if row[5] == 0:
                finished = "Not yet"
            else:
                finished = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[5]))

            retdata.append([row[0], row[1], row[2], created, started, finished, row[6], row[7]])

        return json.dumps(retdata).encode('utf-8')

    scanlist.exposed = True

    def scanstatus(self, id):
        """Basic information about a scan

        Args:
            id (str): scan ID

        Returns:
            str: scan status as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        dbh = SpiderFootDb(self.config)
        data = dbh.scanInstanceGet(id)

        if not data:
            return json.dumps([]).encode('utf-8')

        created = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data[2]))
        started = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data[3]))
        ended = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(data[4]))

        retdata = [data[0], data[1], created, started, ended, data[5]]
        return json.dumps(retdata).encode('utf-8')

    scanstatus.exposed = True

    def scansummary(self, id, by):
        """Summary of scan results

        Args:
            id (str): scan ID
            by: TBD

        Returns:
            scan summary as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        retdata = []

        dbh = SpiderFootDb(self.config)

        try:
            scandata = dbh.scanResultSummary(id, by)
        except Exception:
            return json.dumps(retdata).encode('utf-8')

        try:
            statusdata = dbh.scanInstanceGet(id)
        except Exception:
            return json.dumps(retdata).encode('utf-8')

        for row in scandata:
            if row[0] == "ROOT":
                continue
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[2]))
            retdata.append([row[0], row[1], lastseen, row[3], row[4], statusdata[5]])
        return json.dumps(retdata).encode('utf-8')

    scansummary.exposed = True

    def scaneventresults(self, id, eventType, filterfp=False):
        """Event results for a scan

        Args:
            id (str): scan ID
            eventType (str): filter by event type
            filterfp: TBD

        Returns:
            str: scan results as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        retdata = []

        dbh = SpiderFootDb(self.config)

        try:
            data = dbh.scanResultEvent(id, eventType, filterfp)
        except Exception:
            return json.dumps(retdata).encode('utf-8')

        for row in data:
            lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
            escapeddata = html.escape(row[1])
            escapedsrc = html.escape(row[2])
            retdata.append([lastseen, escapeddata, escapedsrc,
                            row[3], row[5], row[6], row[7], row[8],
                            row[13], row[14], row[4]])
        return json.dumps(retdata).encode('utf-8')

    scaneventresults.exposed = True

    def scaneventresultsunique(self, id, eventType, filterfp=False):
        """Unique event results for a scan

        Args:
            id (str): scan ID
            eventType (str): filter by event type
            filterfp: TBD

        Returns:
            str: unique results as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        dbh = SpiderFootDb(self.config)
        retdata = []

        try:
            data = dbh.scanResultEventUnique(id, eventType, filterfp)
        except Exception:
            return json.dumps(retdata).encode('utf-8')

        for row in data:
            escaped = html.escape(row[0])
            retdata.append([escaped, row[1], row[2]])
        return json.dumps(retdata).encode('utf-8')

    scaneventresultsunique.exposed = True

    def search(self, id=None, eventType=None, value=None):
        """Search

        Args:
            id: TBD
            eventType (str): filter by event type
            value: TBD

        Returns:
            str: search results as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        try:
            search_results = self.searchBase(id, eventType, value)
        except Exception:
            search_results = []

        return json.dumps(search_results).encode('utf-8')

    search.exposed = True

    def scanhistory(self, id):
        """Historical data for a scan.

        Args:
            id (str): scan ID

        Returns:
            str: scan history as JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

        dbh = SpiderFootDb(self.config)

        try:
            scan_history = dbh.scanResultHistory(id)
        except Exception:
            scan_history = []

        return json.dumps(scan_history).encode('utf-8')

    scanhistory.exposed = True

    def scanelementtypediscovery(self, id, eventType):
        """scan element type discovery

        Args:
            id: TBD
            eventType (str): filter by event type

        Returns:
            str: JSON
        """

        cherrypy.response.headers['Content-Type'] = "application/json; charset=utf-8"

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

        return json.dumps(retdata).encode('utf-8')

    scanelementtypediscovery.exposed = True
