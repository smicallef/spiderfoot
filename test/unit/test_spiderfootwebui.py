# test_spiderfootwebui.py
import pytest
import unittest

from sfwebui import SpiderFootWebUi


@pytest.mark.usefixtures
class TestSpiderFootWebUi(unittest.TestCase):
    """
    Test SpiderFootWebUi
    """

    def test_init_no_options_should_raise(self):
        """
        Test __init__(self, config)
        """
        with self.assertRaises(TypeError):
            SpiderFootWebUi(None, None)

        with self.assertRaises(ValueError):
            SpiderFootWebUi(dict(), dict())

    def test_init(self):
        """
        Test __init__(self, config)
        """
        opts = self.default_options
        opts['__modules__'] = dict()

        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        self.assertIsInstance(sfwebui, SpiderFootWebUi)

    def test_error_page(self):
        """
        Test error_page(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()

        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        sfwebui.error_page()

    def test_error_page_404(self):
        """
        Test error_page_404(self, status, message, traceback, version)
        """
        opts = self.default_options
        opts['__modules__'] = dict()

        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        error_page_404 = sfwebui.error_page_404(None, None, None, None)
        self.assertIsInstance(error_page_404, str)

    def test_clean_user_input_should_return_a_list(self):
        """
        Test cleanUserInput(self, inputList)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        clean_user_input = sfwebui.cleanUserInput(list())
        self.assertIsInstance(clean_user_input, list)

    def test_clean_user_input_invalid_input_should_raise(self):
        """
        Test cleanUserInput(self, inputList)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)

        invalid_types = [None, "", dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfwebui.cleanUserInput(invalid_type)

    def test_search_base_should_return_a_list(self):
        """
        Test searchBase(self, id=None, eventType=None, value=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
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
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        search_results = sfwebui.scaneventresultexport("", "", "excel")
        self.assertIsInstance(search_results, bytes)

    def test_scan_event_result_export_multi(self):
        """
        Test scaneventresultexportmulti(self, ids, dialect="excel")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        search_results = sfwebui.scaneventresultexport("", "", "excel")
        self.assertIsInstance(search_results, bytes)

    @unittest.skip("todo")
    def test_scan_search_result_export(self):
        """
        Test scansearchresultexport(self, id, eventType=None, value=None, dialect="excel")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        search_results = sfwebui.scansearchresultexport("", "", "excel")
        self.assertIsInstance(search_results, bytes)

    @unittest.skip("todo")
    def test_scan_export_json_multi(self):
        """
        Test scanexportjsonmulti(self, ids)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        search_results = sfwebui.scanexportjsonmulti(None)
        self.assertIsInstance(search_results, bytes)

    @unittest.skip("todo")
    def test_scan_viz_should_return_a_string(self):
        """
        Test scanviz(self, id, gexf="0")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_viz = sfwebui.scanviz(None, None)
        self.assertIsInstance(scan_viz, str)

    @unittest.skip("todo")
    def test_scan_viz_multi_should_return_a_string(self):
        """
        Test scanvizmulti(self, ids, gexf="1")
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_viz_multi = sfwebui.scanvizmulti(None, None)
        self.assertIsInstance(scan_viz_multi, str)

    @unittest.skip("todo")
    def test_scanopts(self):
        """
        Test scanopts(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_opts = sfwebui.scanopts("example scan instance")
        self.assertIsInstance(scan_opts, str)

        self.assertEqual('TBD', 'TBD')

    def test_rerunscan(self):
        """
        Test rerunscan(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        rerunscan = sfwebui.rerunscan("example scan instance")
        self.assertIsInstance(rerunscan, str)

    @unittest.skip("todo")
    def test_rerunscanmulti(self):
        """
        Test rerunscanmulti(self, ids)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
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
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        clone_scan = sfwebui.clonescan("example scan instance")
        self.assertIsInstance(clone_scan, str)

    def test_index(self):
        """
        Test index(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        index = sfwebui.index()
        self.assertIsInstance(index, str)

    def test_scaninfo(self):
        """
        Test scaninfo(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
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
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        opts_export = sfwebui.optsexport(None)
        self.assertIsInstance(opts_export, str)

    def test_optsraw_should_return_bytes(self):
        """
        Test optsraw(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        opts_raw = sfwebui.optsraw()
        self.assertIsInstance(opts_raw, bytes)

    def test_error(self):
        """
        Test error(self, message)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)

        message = "example message"
        scan_error = sfwebui.error(message)
        self.assertIsInstance(scan_error, str)
        self.assertIn("example message", scan_error)

    def test_scandelete_invalid_scanid_should_return_an_error(self):
        """
        Test scandelete(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_delete = sfwebui.scandelete("example scan id")
        self.assertIsInstance(scan_delete, dict)
        self.assertEqual("Scan example scan id does not exist", scan_delete.get('error').get('message'))

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

    def test_eventtypes_should_return_bytes(self):
        """
        Test eventtypes(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        event_types = sfwebui.eventtypes()
        self.assertIsInstance(event_types, bytes)

    def test_modules_should_return_bytes(self):
        """
        Test modules(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        modules = sfwebui.eventtypes()
        self.assertIsInstance(modules, bytes)

    def test_ping_should_return_bytes(self):
        """
        Test ping(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        ping = sfwebui.ping()
        self.assertIsInstance(ping, bytes)

    def test_query_should_perform_a_sql_query(self):
        """
        Test query(self, query)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        query = sfwebui.query("SELECT 12345")
        self.assertIsInstance(query, bytes)
        self.assertIn(b"12345", query)

    @unittest.skip("todo")
    def test_start_scan(self):
        """
        Test startscan(self, scanname, scantarget, modulelist, typelist, usecase)
        """
        self.assertEqual('TBD', 'TBD')

    def test_stopscanmulti(self):
        """
        Test stopscanmulti(self, ids)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        stop_scan = sfwebui.stopscanmulti("example scan id")
        self.assertIsInstance(stop_scan, str)

    @unittest.skip("todo")
    def test_stopscan(self):
        """
        Test stopscan(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        stop_scan = sfwebui.stopscan("example scan id")
        self.assertIsInstance(stop_scan, str)

    def test_scanlog_should_return_bytes(self):
        """
        Test scanlog(self, id, limit=None, rowId=None, reverse=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_log = sfwebui.scanlog(None, None, None, None)
        self.assertIsInstance(scan_log, bytes)

    def test_scanerrors_should_return_bytes(self):
        """
        Test scanerrors(self, id, limit=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_errors = sfwebui.scanerrors(None, None)
        self.assertIsInstance(scan_errors, bytes)

    def test_scanlist_should_return_bytes(self):
        """
        Test scanlist(self)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_list = sfwebui.scanlist()
        self.assertIsInstance(scan_list, bytes)

    def test_scanstatus_should_return_bytes(self):
        """
        Test scanstatus(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_status = sfwebui.scanstatus("example scan instance")
        self.assertIsInstance(scan_status, bytes)

    def test_scansummary_should_return_bytes(self):
        """
        Test scansummary(self, id, by)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_summary = sfwebui.scansummary(None, None)
        self.assertIsInstance(scan_summary, bytes)

    def test_scaneventresults_should_return_bytes(self):
        """
        Test scaneventresults(self, id, eventType, filterfp=False)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_results = sfwebui.scaneventresults(None, None, None)
        self.assertIsInstance(scan_results, bytes)

    @unittest.skip("todo")
    def test_scaneventresultsunique_should_return_a_string(self):
        """
        Test scaneventresultsunique(self, id, eventType, filterfp=False)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_results = sfwebui.scaneventresultsunique(None, None, None)
        self.assertIsInstance(scan_results, str)

    def test_search_should_return_bytes(self):
        """
        Test search(self, id=None, eventType=None, value=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        search_results = sfwebui.search(None, None, None)
        self.assertIsInstance(search_results, bytes)

    def test_scan_history_should_return_bytes(self):
        """
        Test scanhistory(self, id)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_history = sfwebui.scanhistory(None)
        self.assertIsInstance(scan_history, bytes)

    @unittest.skip("todo")
    def test_scan_element_type_discovery_should_return_a_string(self):
        """
        Test scanelementtypediscovery(self, id, eventType)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        sfwebui = SpiderFootWebUi(self.web_default_options, opts)
        scan_element_type_discovery = sfwebui.scanelementtypediscovery(None, None)
        self.assertIsInstance(scan_element_type_discovery, str)
