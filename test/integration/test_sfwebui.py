# test_sfwebui.py
import os
import unittest

import cherrypy
from cherrypy.test import helper

from spiderfoot import SpiderFootHelpers
from sfwebui import SpiderFootWebUi


class TestSpiderFootWebUiRoutes(helper.CPWebCase):
    @staticmethod
    def setup_server():
        default_config = {
            '_debug': False,  # Debug
            '__logging': True,  # Logging in general
            '__outputfilter': None,  # Event types to filter from modules' output
            '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',  # User-Agent to use for HTTP requests
            '_dnsserver': '',  # Override the default resolver
            '_fetchtimeout': 5,  # number of seconds before giving up on a fetch
            '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
            '_internettlds_cache': 72,
            '_genericusers': ",".join(SpiderFootHelpers.usernamesFromWordlists(['generic-usernames'])),
            '__database': f"{SpiderFootHelpers.dataPath()}/spiderfoot.test.db",  # note: test database file
            '__modules__': None,  # List of modules. Will be set after start-up.
            '__correlationrules__': None,  # List of correlation rules. Will be set after start-up.
            '_socks1type': '',
            '_socks2addr': '',
            '_socks3port': '',
            '_socks4user': '',
            '_socks5pwd': '',
            '__logstdout': False
        }

        default_web_config = {
            'root': '/'
        }

        mod_dir = os.path.dirname(os.path.abspath(__file__)) + '/../../modules/'
        default_config['__modules__'] = SpiderFootHelpers.loadModulesAsDict(mod_dir, ['sfp_template.py'])

        conf = {
            '/query': {
                'tools.encode.text_only': False,
                'tools.encode.add_charset': True,
            },
            '/static': {
                'tools.staticdir.on': True,
                'tools.staticdir.dir': 'static',
                'tools.staticdir.root': f"{os.path.dirname(os.path.abspath(__file__))}/../../spiderfoot",
            }
        }

        cherrypy.tree.mount(SpiderFootWebUi(default_web_config, default_config), script_name=default_web_config.get('root'), config=conf)

    def test_invalid_page_returns_404(self):
        self.getPage("/doesnotexist")
        self.assertStatus('404 Not Found')

    def test_static_returns_200(self):
        self.getPage("/static/img/spiderfoot-header.png")
        self.assertStatus('200 OK')

    def test_scaneventresultexport_invalid_scan_id_returns_200(self):
        self.getPage("/scaneventresultexport?id=doesnotexist&type=doesnotexist")
        self.assertStatus('200 OK')

    def test_scaneventresultexportmulti(self):
        self.getPage("/scaneventresultexportmulti?ids=doesnotexist")
        self.assertStatus('200 OK')

    def test_scansearchresultexport(self):
        self.getPage("/scansearchresultexport?id=doesnotexist")
        self.assertStatus('200 OK')

    def test_scanexportjsonmulti(self):
        self.getPage("/scanexportjsonmulti?ids=doesnotexist")
        self.assertStatus('200 OK')

    def test_scanviz(self):
        self.getPage("/scanviz?id=doesnotexist")
        self.assertStatus('200 OK')

    def test_scanvizmulti(self):
        self.getPage("/scanvizmulti?ids=doesnotexist")
        self.assertStatus('200 OK')

    def test_scanopts_invalid_scan_returns_200(self):
        self.getPage("/scanopts?id=doesnotexist")
        self.assertStatus('200 OK')

    def test_rerunscan(self):
        self.getPage("/rerunscan?id=doesnotexist")
        self.assertStatus('200 OK')
        self.assertInBody("Invalid scan ID.")

    def test_rerunscanmulti_invalid_scan_id_returns_200(self):
        self.getPage("/rerunscanmulti?ids=doesnotexist")
        self.assertStatus('200 OK')
        self.assertInBody("Invalid scan ID.")

    def test_newscan_returns_200(self):
        self.getPage("/newscan")
        self.assertStatus('200 OK')
        self.assertInBody("Scan Name")
        self.assertInBody("Scan Target")

    def test_clonescan(self):
        self.getPage("/clonescan?id=doesnotexist")
        self.assertStatus('200 OK')
        self.assertInBody("Invalid scan ID.")

    def test_index_returns_200(self):
        self.getPage("/")
        self.assertStatus('200 OK')

    def test_scaninfo_invalid_scan_returns_200(self):
        self.getPage("/scaninfo?id=doesnotexist")
        self.assertStatus('200 OK')
        self.assertInBody("Scan ID not found.")

    @unittest.skip("todo")
    def test_opts_returns_200(self):
        self.getPage("/opts")
        self.assertStatus('200 OK')

    def test_optsexport(self):
        self.getPage("/optsexport")
        self.assertStatus('200 OK')
        self.getPage("/optsexport?pattern=api_key")
        self.assertStatus('200 OK')
        self.assertHeader("Content-Disposition", "attachment; filename=\"SpiderFoot.cfg\"")
        self.assertInBody(":api_key=")

    def test_optsraw(self):
        self.getPage("/optsraw")
        self.assertStatus('200 OK')

    def test_scandelete_invalid_scan_id_returns_404(self):
        self.getPage("/scandelete?id=doesnotexist")
        self.assertStatus('404 Not Found')
        self.assertInBody('Scan doesnotexist does not exist')

    @unittest.skip("todo")
    def test_savesettings(self):
        self.getPage("/savesettings")
        self.assertStatus('200 OK')

    @unittest.skip("todo")
    def test_savesettingsraw(self):
        self.getPage("/savesettingsraw")
        self.assertStatus('200 OK')

    def test_resultsetfp(self):
        self.getPage("/resultsetfp?id=doesnotexist&resultids=doesnotexist&fp=1")
        self.assertStatus('200 OK')
        self.assertInBody("No IDs supplied.")

    def test_eventtypes(self):
        self.getPage("/eventtypes")
        self.assertStatus('200 OK')
        self.assertInBody('"DOMAIN_NAME"')

    def test_modules(self):
        self.getPage("/modules")
        self.assertStatus('200 OK')
        self.assertInBody('"name":')

    def test_ping_returns_200(self):
        self.getPage("/ping")
        self.assertStatus('200 OK')
        self.assertInBody('"SUCCESS"')

    def test_query_returns_200(self):
        self.getPage("/query?query=SELECT+1")
        self.assertStatus('200 OK')
        self.assertInBody('[{"1": 1}]')

    def test_startscan_invalid_scan_name_returns_error(self):
        self.getPage("/startscan?scanname=&scantarget=&modulelist=&typelist=&usecase=")
        self.assertStatus('200 OK')
        self.assertInBody('Invalid request: scan name was not specified.')

    def test_startscan_invalid_scan_target_returns_error(self):
        self.getPage("/startscan?scanname=example-scan&scantarget=&modulelist=&typelist=&usecase=")
        self.assertStatus('200 OK')
        self.assertInBody('Invalid request: scan target was not specified.')

    def test_startscan_unrecognized_scan_target_returns_error(self):
        self.getPage("/startscan?scanname=example-scan&scantarget=invalid-target&modulelist=doesnotexist&typelist=doesnotexist&usecase=doesnotexist")
        self.assertStatus('200 OK')
        self.assertInBody('Invalid target type. Could not recognize it as a target SpiderFoot supports.')

    def test_startscan_invalid_modules_returns_error(self):
        self.getPage("/startscan?scanname=example-scan&scantarget=spiderfoot.net&modulelist=&typelist=&usecase=")
        self.assertStatus('200 OK')
        self.assertInBody('Invalid request: no modules specified for scan.')

    def test_startscan_invalid_typelist_returns_error(self):
        self.getPage("/startscan?scanname=example-scan&scantarget=spiderfoot.net&modulelist=&typelist=doesnotexist&usecase=")
        self.assertStatus('200 OK')
        self.assertInBody('Invalid request: no modules specified for scan.')

    def test_startscan_should_start_a_scan(self):
        self.getPage("/startscan?scanname=spiderfoot.net&scantarget=spiderfoot.net&modulelist=doesnotexist&typelist=doesnotexist&usecase=doesnotexist")
        self.assertStatus('303 See Other')

    def test_stopscan_invalid_scan_id_returns_404(self):
        self.getPage("/stopscan?id=doesnotexist")
        self.assertStatus('404 Not Found')
        self.assertInBody('Scan doesnotexist does not exist')

    def test_scanlog_invalid_scan_returns_200(self):
        self.getPage("/scanlog?id=doesnotexist")
        self.assertStatus('200 OK')

    def test_scanerrors_invalid_scan_returns_200(self):
        self.getPage("/scanerrors?id=doesnotexist")
        self.assertStatus('200 OK')

    def test_scanlist_returns_200(self):
        self.getPage("/scanlist")
        self.assertStatus('200 OK')

    def test_scanstatus_invalid_scan_returns_200(self):
        self.getPage("/scanstatus?id=doesnotexist")
        self.assertStatus('200 OK')

    def test_scansummary_invalid_scan_returns_200(self):
        self.getPage("/scansummary?id=doesnotexist&by=anything")
        self.assertStatus('200 OK')

    def test_scaneventresults_invalid_scan_returns_200(self):
        self.getPage("/scaneventresults?id=doesnotexist&eventType=anything")
        self.assertStatus('200 OK')

    def test_scaneventresultsunique_invalid_scan_returns_200(self):
        self.getPage("/scaneventresultsunique?id=doesnotexist&eventType=anything")
        self.assertStatus('200 OK')

    def test_search_returns_200(self):
        self.getPage("/search?id=doesnotexist&eventType=doesnotexist&value=doesnotexist")
        self.assertStatus('200 OK')

    def test_scanhistory_invalid_scan_returns_200(self):
        self.getPage("/scanhistory?id=doesnotexist")
        self.assertStatus('200 OK')

    def test_scanelementtypediscovery_invalid_scan_id_returns_200(self):
        self.getPage("/scanelementtypediscovery?id=doesnotexist&eventType=anything")
        self.assertStatus('200 OK')
