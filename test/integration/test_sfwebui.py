# test_sfwebui.py
import os
import unittest

import cherrypy
from cherrypy.test import helper

from sflib import SpiderFoot
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
            '_genericusers': "abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,ispsupport,list-request,list,maildaemon,marketing,noc,no-reply,noreply,null,peering,peering-notify,peering-request,phish,phishing,postmaster,privacy,registrar,registry,root,routing-registry,rr,sales,security,spam,support,sysadmin,tech,undisclosed-recipients,unsubscribe,usenet,uucp,webmaster,www",
            '__database': 'spiderfoot.test.db',  # note: test database file
            '__modules__': None,  # List of modules. Will be set after start-up.
            '_socks1type': '',
            '_socks2addr': '',
            '_socks3port': '',
            '_socks4user': '',
            '_socks5pwd': '',
            '_torctlport': 9051,
            '__logstdout': False
        }

        default_web_config = {
            'root': '/'
        }

        sfModules = dict()
        sf = SpiderFoot(default_config)
        mod_dir = sf.myPath() + '/modules/'
        for filename in os.listdir(mod_dir):
            if filename.startswith("sfp_") and filename.endswith(".py"):
                # Skip the module template and debugging modules
                if filename == "sfp_template.py" or filename == 'sfp_stor_print.py':
                    continue
                modName = filename.split('.')[0]

                # Load and instantiate the module
                sfModules[modName] = dict()
                mod = __import__('modules.' + modName, globals(), locals(), [modName])
                sfModules[modName]['object'] = getattr(mod, modName)()
                sfModules[modName]['name'] = sfModules[modName]['object'].meta['name']
                sfModules[modName]['cats'] = sfModules[modName]['object'].meta.get('categories', list())
                sfModules[modName]['group'] = sfModules[modName]['object'].meta.get('useCases', list())
                if len(sfModules[modName]['cats']) > 1:
                    raise ValueError(f"Module {modName} has multiple categories defined but only one is supported.")
                sfModules[modName]['labels'] = sfModules[modName]['object'].meta.get('flags', list())
                sfModules[modName]['descr'] = sfModules[modName]['object'].meta['summary']
                sfModules[modName]['provides'] = sfModules[modName]['object'].producedEvents()
                sfModules[modName]['consumes'] = sfModules[modName]['object'].watchedEvents()
                sfModules[modName]['meta'] = sfModules[modName]['object'].meta
                if hasattr(sfModules[modName]['object'], 'opts'):
                    sfModules[modName]['opts'] = sfModules[modName]['object'].opts
                if hasattr(sfModules[modName]['object'], 'optdescs'):
                    sfModules[modName]['optdescs'] = sfModules[modName]['object'].optdescs

        default_config['__modules__'] = sfModules

        conf = {
            '/query': {
                'tools.encode.text_only': False,
                'tools.encode.add_charset': True,
            },
            '/static': {
                'tools.staticdir.on': True,
                'tools.staticdir.dir': 'static',
                'tools.staticdir.root': sf.myPath()
            }
        }

        cherrypy.tree.mount(SpiderFootWebUi(default_web_config, default_config), script_name=default_web_config.get('root'), config=conf)

    def test_invalid_page_returns_404(self):
        self.getPage("/doesnotexist")
        self.assertStatus('404 Not Found')

    def test_static_returns_200(self):
        self.getPage("/static/img/spiderfoot-header.png")
        self.assertStatus('200 OK')

    @unittest.skip("todo")
    def test_scaneventresultexport(self):
        self.getPage("/scaneventresultexport")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scaneventresultexportmulti(self):
        self.getPage("/scaneventresultexportmulti")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scansearchresultexport(self):
        self.getPage("/scansearchresultexport")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scanexportjsonmulti(self):
        self.getPage("/scanexportjsonmulti")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scanviz(self):
        self.getPage("/scanviz")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scanvizmulti(self):
        self.getPage("/scanvizmulti")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    def test_scanopts_invalid_scan_returns_200(self):
        self.getPage("/scanopts?id=doesnotexist")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    def test_rerunscan(self):
        self.getPage("/rerunscan?id=doesnotexist")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_rerunscanmulti(self):
        self.getPage("/rerunscanmulti?id=doesnotexist")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    def test_newscan_returns_200(self):
        self.getPage("/newscan")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    def test_clonescan(self):
        self.getPage("/clonescan?id=doesnotexist")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    def test_index_returns_200(self):
        self.getPage("/")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    def test_scaninfo_invalid_scan_returns_200(self):
        self.getPage("/scaninfo?id=doesnotexist")
        self.assertStatus('200 OK')

    @unittest.skip("todo")
    def test_opts_returns_200(self):
        self.getPage("/opts")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_optsexport(self):
        self.getPage("/optsexport")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_optsraw(self):
        self.getPage("/optsraw")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scandelete_invalid_scan_returns_200(self):
        self.getPage("/scandelete?id=doesnotexist")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scandeletemulti(self):
        self.getPage("/scandeletemulti?ids=doesnotexist")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_savesettings(self):
        self.getPage("/savesettings")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_savesettingsraw(self):
        self.getPage("/savesettingsraw")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_resultsetfp(self):
        self.getPage("/resultsetfp?id=doesnotexist&resultids=doesnotexist&fp=1")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    def test_eventtypes(self):
        self.getPage("/eventtypes")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    def test_modules(self):
        self.getPage("/modules")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    def test_ping_returns_200(self):
        self.getPage("/ping")
        self.assertStatus('200 OK')

    def test_query_returns_200(self):
        self.getPage("/query?query=anything")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_startscan(self):
        self.getPage("/startscan")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_stopscanmulti(self):
        self.getPage("/stopscanmulti")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_stopscan(self):
        self.getPage("/stopscan")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

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
        self.getPage("/search")
        self.assertStatus('200 OK')

    def test_scanhistory_invalid_scan_returns_200(self):
        self.getPage("/scanhistory?id=doesnotexist")
        self.assertStatus('200 OK')

    @unittest.skip("todo")
    def test_scanelementtypediscovery_invalid_scan_returns_200(self):
        self.getPage("/scanelementtypediscovery?id=doesnotexist&eventType=anything")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')
