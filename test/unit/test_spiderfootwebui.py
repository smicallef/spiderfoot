# test_spiderfootwebui.py
from sfwebui import SpiderFootWebUi
import unittest

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

    @unittest.skip("todo")
    def test_error_page_404(self):
        """
        Test error_page_404(self, status, message, traceback, version)
        """
        sfwebui = SpiderFootWebUi(self.default_options)
        sfwebui.error_page_404(None, None, None, None, None)

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
        self.assertEqual('TBD', 'TBD')

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

    @unittest.skip("todo")
    def test_rerunscan(self):
        """
        Test rerunscan(self, id)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_rerunscanmulti(self):
        """
        Test rerunscanmulti(self, ids)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_newscan(self):
        """
        Test newscan(self)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_clonescan(self):
        """
        Test clonescan(self, id)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_index(self):
        """
        Test index(self)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scaninfo(self):
        """
        Test scaninfo(self, id)
        """
        self.assertEqual('TBD', 'TBD')

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

    @unittest.skip("todo")
    def test_scandelete(self):
        """
        Test scandelete(self, id, confirm=None, raw=False)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scandeletemulti(self):
        """
        Test scandeletemulti(self, ids, confirm=None)
        """
        self.assertEqual('TBD', 'TBD')

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

    @unittest.skip("todo")
    def test_stopscanmulti(self):
        """
        Test stopscanmulti(self, ids)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_stopscan(self):
        """
        Test stopscan(self, id, cli=None)
        """
        self.assertEqual('TBD', 'TBD')

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

    @unittest.skip("todo")
    def test_scanstatus_should_return_a_string(self):
        """
        Test scanstatus(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(opts)
        scan_status = sfwebui.scanstatus(None)
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

