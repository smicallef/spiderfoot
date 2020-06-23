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

    @unittest.skip("todo")
    def test_cleanUserInput(self):
        """
        Test cleanUserInput(self, inputList)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_search_base(self):
        """
        Test searchBase(self, id=None, eventType=None, value=None)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_event_result_export(self):
        """
        Test scaneventresultexport(self, id, type, dialect="excel")
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_event_result_export_multi(self):
        """
        Test scaneventresultexportmulti(self, ids, dialect="excel")
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_search_result_export(self):
        """
        Test scansearchresultexport(self, id, eventType=None, value=None, dialect="excel")
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_export_json_multi(self):
        """
        Test scanexportjsonmulti(self, ids)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_viz(self):
        """
        Test scanviz(self, id, gexf="0")
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_viz_multi(self):
        """
        Test scanvizmulti(self, ids, gexf="1")
        """
        self.assertEqual('TBD', 'TBD')

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

    @unittest.skip("todo")
    def test_optsexport(self):
        """
        Test optsexport(self, pattern)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_optsraw(self):
        """
        Test optsraw(self)
        """
        self.assertEqual('TBD', 'TBD')

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

    @unittest.skip("todo")
    def test_eventtypes(self):
        """
        Test eventtypes(self)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_modules(self):
        """
        Test modules(self)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_ping(self):
        """
        Test ping(self)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_query(self):
        """
        Test query(self, query)
        """
        self.assertEqual('TBD', 'TBD')

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

    @unittest.skip("todo")
    def test_scanlog(self):
        """
        Test scanlog(self, id, limit=None, rowId=None, reverse=None)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scanerrors(self):
        """
        Test scanerrors(self, id, limit=None)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scanlist(self):
        """
        Test scanlist(self)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scanstatus(self):
        """
        Test scanstatus(self, id)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scansummary(self):
        """
        Test scansummary(self, id, by)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scaneventresults(self):
        """
        Test scaneventresults(self, id, eventType, filterfp=False)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scaneventresultsunique(self):
        """
        Test scaneventresultsunique(self, id, eventType, filterfp=False)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_search(self):
        """
        Test search(self, id=None, eventType=None, value=None)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_history(self):
        """
        Test scanhistory(self, id)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_element_type_discovery(self):
        """
        Test scanelementtypediscovery(self, id, eventType)
        """
        self.assertEqual('TBD', 'TBD')

if __name__ == '__main__':
    unittest.main()

