# test_spiderfootwebui.py
from sfwebui import SpiderFootWebUi
from sflib import SpiderFoot
import unittest
import cherrypy
from cherrypy.test import helper
import os

class TestSpiderFootWebUiRoutes(helper.CPWebCase):
    @staticmethod
    def setup_server():
        default_config = {
            '_debug': False,  # Debug
            '__logging': True, # Logging in general
            '__outputfilter': None, # Event types to filter from modules' output
            '__blocknotif': False,  # Block notifications
            '_fatalerrors': False,
            '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',  # User-Agent to use for HTTP requests
            '_dnsserver': '',  # Override the default resolver
            '_fetchtimeout': 5,  # number of seconds before giving up on a fetch
            '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
            '_internettlds_cache': 72,
            '_genericusers': "abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,ispsupport,list-request,list,maildaemon,marketing,noc,no-reply,noreply,null,peering,peering-notify,peering-request,phish,phishing,postmaster,privacy,registrar,registry,root,routing-registry,rr,sales,security,spam,support,sysadmin,tech,undisclosed-recipients,unsubscribe,usenet,uucp,webmaster,www",
            '__version__': '3.0',
            '__database': 'spiderfoot.test.db',  # note: test database file
            '__webaddr': '127.0.0.1',
            '__webport': 5001,
            '__docroot': '',  # don't put trailing /
            '__modules__': None,  # List of modules. Will be set after start-up.
            '_socks1type': '',
            '_socks2addr': '',
            '_socks3port': '',
            '_socks4user': '',
            '_socks5pwd': '',
            '_socks6dns': True,
            '_torctlport': 9051,
            '__logstdout': False
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
                sfModules[modName]['name'] = sfModules[modName]['object'].__doc__.split(":", 5)[0]
                sfModules[modName]['cats'] = sfModules[modName]['object'].__doc__.split(":", 5)[1].split(",")
                sfModules[modName]['group'] = sfModules[modName]['object'].__doc__.split(":", 5)[2]
                sfModules[modName]['labels'] = sfModules[modName]['object'].__doc__.split(":", 5)[3].split(",")
                sfModules[modName]['descr'] = sfModules[modName]['object'].__doc__.split(":", 5)[4]
                sfModules[modName]['provides'] = sfModules[modName]['object'].producedEvents()
                sfModules[modName]['consumes'] = sfModules[modName]['object'].watchedEvents()
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
                'tools.staticdir.dir': os.path.join(sf.myPath(), 'static')
            }
        }

        cherrypy.tree.mount(SpiderFootWebUi(default_config), default_config['__docroot'], config=conf)

    def test_invalid_page_returns_404(self):
        data = self.getPage("/doesnotexist")
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

    @unittest.skip("todo")
    def test_rerunscan(self):
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_rerunscanmulti(self):
        self.assertEqual('TBD', 'TBD')

    def test_newscan_returns_200(self):
        self.getPage("/newscan")
        self.assertStatus('200 OK')

    @unittest.skip("todo")
    def test_clonescan(self):
        self.assertEqual('TBD', 'TBD')

    def test_index_returns_200(self):
        self.getPage("/")
        self.assertStatus('200 OK')

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
        self.getPage("/resultsetfp")
        self.assertStatus('200 OK')

        self.assertEqual('TBD', 'TBD')

    def test_eventtypes(self):
        self.getPage("/eventtypes")
        self.assertStatus('200 OK')

    def test_modules(self):
        self.getPage("/modules")
        self.assertStatus('200 OK')

    def test_ping_returns_200(self):
        self.getPage("/ping")
        self.assertStatus('200 OK')

    def test_query_returns_200(self):
        self.getPage("/query?query=anything")
        self.assertStatus('200 OK')

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

class TestSpiderFootWebUi(unittest.TestCase):
    """
    Test SpiderFootWebUi
    """
    default_options = {
      '_debug': False,
      '__logging': True,
      '__outputfilter': None,
      '__blocknotif': False,
      '_fatalerrors': False,
      '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
      '_dnsserver': '',
      '_fetchtimeout': 5,
      '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
      '_internettlds_cache': 72,
      '_genericusers': "abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,ispsupport,list-request,list,maildaemon,marketing,noc,no-reply,noreply,null,peering,peering-notify,peering-request,phish,phishing,postmaster,privacy,registrar,registry,root,routing-registry,rr,sales,security,spam,support,sysadmin,tech,undisclosed-recipients,unsubscribe,usenet,uucp,webmaster,www",
      '__version__': '3.0',
      '__database': 'spiderfoot.test.db',  # note: test database file
      '__webaddr': '127.0.0.1',
      '__webport': 5001,
      '__docroot': '',
      '__modules__': None,
      '_socks1type': '',
      '_socks2addr': '',
      '_socks3port': '',
      '_socks4user': '',
      '_socks5pwd': '',
      '_socks6dns': True,
      '_torctlport': 9051,
      '__logstdout': False
    }

    def test_init_no_options_should_raise(self):
        """
        Test __init__(self, config)
        """
        with self.assertRaises(TypeError) as cm:
            sfwebui = SpiderFootWebUi(None)

        with self.assertRaises(ValueError) as cm:
            sfwebui = SpiderFootWebUi(dict())

    @unittest.skip("todo")
    def test_init(self):
        """
        Test __init__(self, config)
        """
        sfwebui = SpiderFootWebUi(self.default_options)
        self.assertIsInstance(sfwebui, SpiderFootWebUi)
 
    @unittest.skip("todo")
    def test_error_page(self):
        """
        Test error_page(self)
        """
        sfwebui = SpiderFootWebUi(self.default_options)
        sfwebui.error_page()

    def test_error_page_404(self):
        """
        Test error_page_404(self, status, message, traceback, version)
        """
        sfwebui = SpiderFootWebUi(self.default_options)
        error_page_404 = sfwebui.error_page_404(None, None, None, None)
        self.assertIsInstance(error_page_404, str)

    def test_clean_user_input_should_return_a_list(self):
        """
        Test cleanUserInput(self, inputList)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        clean_user_input = sfwebui.cleanUserInput(list())
        self.assertIsInstance(clean_user_input, list)

    def test_clean_user_input_invalid_input_should_raise(self):
        """
        Test cleanUserInput(self, inputList)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)

        invalid_types = [None, "", dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    clean_user_input = sfwebui.cleanUserInput(invalid_type)

    def test_search_base_should_return_a_list(self):
        """
        Test searchBase(self, id=None, eventType=None, value=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        search_results = sfwebui.searchBase(None, None, None)
        self.assertIsInstance(search_results, list)

        search_results = sfwebui.searchBase(None, None, "//")
        self.assertIsInstance(search_results, list)

    def test_scan_event_result_export_should_return_bytes(self):
        """
        Test scaneventresultexport(self, id, type, dialect="excel")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        search_results = sfwebui.scaneventresultexport("", "", "excel")
        self.assertIsInstance(search_results, bytes)

    def test_scan_event_result_export_multi(self):
        """
        Test scaneventresultexportmulti(self, ids, dialect="excel")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        search_results = sfwebui.scaneventresultexport("", "", "excel")
        self.assertIsInstance(search_results, bytes)

    @unittest.skip("todo")
    def test_scan_search_result_export(self):
        """
        Test scansearchresultexport(self, id, eventType=None, value=None, dialect="excel")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        search_results = sfwebui.scansearchresultexport("", "", "excel")
        self.assertIsInstance(search_results, bytes)

    @unittest.skip("todo")
    def test_scan_export_json_multi(self):
        """
        Test scanexportjsonmulti(self, ids)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        search_results = sfwebui.scanexportjsonmulti(None)
        self.assertIsInstance(search_results, bytes)

    @unittest.skip("todo")
    def test_scan_viz_should_return_a_string(self):
        """
        Test scanviz(self, id, gexf="0")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_viz = sfwebui.scanviz(None, None)
        self.assertIsInstance(scan_viz, str)

    @unittest.skip("todo")
    def test_scan_viz_multi_should_return_a_string(self):
        """
        Test scanvizmulti(self, ids, gexf="1")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_viz_multi = sfwebui.scanvizmulti(None, None)
        self.assertIsInstance(scan_viz_multi, str)

    @unittest.skip("todo")
    def test_scanopts(self):
        """
        Test scanopts(self, id)
        """
        self.assertEqual('TBD', 'TBD')

    def test_rerunscan(self):
        """
        Test rerunscan(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        rerunscan = sfwebui.rerunscan("example scan instance")
        self.assertIsInstance(rerunscan, str)

    @unittest.skip("todo")
    def test_rerunscanmulti(self):
        """
        Test rerunscanmulti(self, ids)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        rerunscanmulti = sfwebui.rerunscanmulti("example scan instance")
        self.assertIsInstance(rerunscanmulti, str)

    @unittest.skip("todo")
    def test_newscan(self):
        """
        Test newscan(self)
        """
        self.assertEqual('TBD', 'TBD')

    def test_clonescan(self):
        """
        Test clonescan(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        clone_scan = sfwebui.clonescan("example scan instance")
        self.assertIsInstance(clone_scan, str)

    def test_index(self):
        """
        Test index(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        index = sfwebui.index()
        self.assertIsInstance(index, str)

    def test_scaninfo(self):
        """
        Test scaninfo(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_info = sfwebui.scaninfo("example scan instance")
        self.assertIsInstance(scan_info, str)

    @unittest.skip("todo")
    def test_opts(self):
        """
        Test opts(self)
        """
        self.assertEqual('TBD', 'TBD')

    def test_optsexport_should_return_a_string(self):
        """
        Test optsexport(self, pattern)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        opts_export = sfwebui.optsexport(None)
        self.assertIsInstance(opts_export, str)

    def test_optsraw_should_return_a_string(self):
        """
        Test optsraw(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        opts_raw = sfwebui.optsraw()
        self.assertIsInstance(opts_raw, str)

    @unittest.skip("todo")
    def test_error(self):
        """
        Test error(self, message)
        """
        self.assertEqual('TBD', 'TBD')

    def test_scandelete(self):
        """
        Test scandelete(self, id, confirm=None, raw=False)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_delete = sfwebui.scandelete("example scan id", None, None)
        self.assertIsInstance(scan_delete, str)

    @unittest.skip("todo")
    def test_scandeletemulti(self):
        """
        Test scandeletemulti(self, ids, confirm=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_delete = sfwebui.scandeletemulti("example scan id", None)
        self.assertIsInstance(scan_delete, str)

    @unittest.skip("todo")
    def test_savesettings(self):
        """
        Test savesettings(self, allopts, token, configFile=None)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_savesettingsraw(self):
        """
        Test savesettingsraw(self, allopts, token)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_result_set_fp(self):
        """
        Test resultsetfp(self, id, resultids, fp)
        """
        self.assertEqual('TBD', 'TBD')

    def test_eventtypes_should_return_a_string(self):
        """
        Test eventtypes(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        event_types = sfwebui.eventtypes()
        self.assertIsInstance(event_types, str)

    def test_modules_should_return_a_string(self):
        """
        Test modules(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        modules = sfwebui.eventtypes()
        self.assertIsInstance(modules, str)

    def test_ping_should_return_a_string(self):
        """
        Test ping(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        ping = sfwebui.ping()
        self.assertIsInstance(ping, str)

    def test_query_should_perform_a_sql_query(self):
        """
        Test query(self, query)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        query = sfwebui.query("SELECT 12345")
        self.assertIsInstance(query, str)
        self.assertIn("12345", query)

    @unittest.skip("todo")
    def test_start_scan(self):
        """
        Test startscan(self, scanname, scantarget, modulelist, typelist, usecase, cli=None)
        """
        self.assertEqual('TBD', 'TBD')

    def test_stopscanmulti(self):
        """
        Test stopscanmulti(self, ids)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        stop_scan = sfwebui.stopscanmulti("example scan id")
        self.assertIsInstance(stop_scan, str)

    def test_stopscan(self):
        """
        Test stopscan(self, id, cli=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        stop_scan = sfwebui.stopscan("example scan id")
        self.assertIsInstance(stop_scan, str)

    def test_scanlog_should_return_a_string(self):
        """
        Test scanlog(self, id, limit=None, rowId=None, reverse=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_log = sfwebui.scanlog(None, None, None, None)
        self.assertIsInstance(scan_log, str)

    def test_scanerrors_should_return_a_string(self):
        """
        Test scanerrors(self, id, limit=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_errors = sfwebui.scanerrors(None, None)
        self.assertIsInstance(scan_errors, str)

    def test_scanlist_should_return_a_string(self):
        """
        Test scanlist(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_list = sfwebui.scanlist()
        self.assertIsInstance(scan_list, str)

    def test_scanstatus_should_return_a_string(self):
        """
        Test scanstatus(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_status = sfwebui.scanstatus("example scan instance")
        self.assertIsInstance(scan_status, str)

    def test_scansummary_should_return_a_string(self):
        """
        Test scansummary(self, id, by)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_summary = sfwebui.scansummary(None, None)
        self.assertIsInstance(scan_summary, str)

    def test_scaneventresults_should_return_a_string(self):
        """
        Test scaneventresults(self, id, eventType, filterfp=False)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_results = sfwebui.scaneventresults(None, None, None)
        self.assertIsInstance(scan_results, str)

    @unittest.skip("todo")
    def test_scaneventresultsunique_should_return_a_string(self):
        """
        Test scaneventresultsunique(self, id, eventType, filterfp=False)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_results = sfwebui.scaneventresultsunique(None, None, None)
        self.assertIsInstance(scan_results, str)

    def test_search_should_return_a_string(self):
        """
        Test search(self, id=None, eventType=None, value=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        search_results = sfwebui.search(None, None, None)
        self.assertIsInstance(search_results, str)

    def test_scan_history_should_return_a_string(self):
        """
        Test scanhistory(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_history = sfwebui.scanhistory(None)
        self.assertIsInstance(scan_history, str)

    @unittest.skip("todo")
    def test_scan_element_type_discovery_should_return_a_string(self):
        """
        Test scanelementtypediscovery(self, id, eventType)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_element_type_discovery = sfwebui.scanelementtypediscovery(None, None)
        self.assertIsInstance(scan_element_type_discovery, str)

if __name__ == '__main__':
    unittest.main()

