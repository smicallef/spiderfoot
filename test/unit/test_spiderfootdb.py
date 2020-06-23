# test_spiderfootdb.py
from sfdb import SpiderFootDb
import unittest

class TestSpiderFootDb(unittest.TestCase):
    """
    Test SpiderFootDb
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

    @unittest.skip("todo")
    def test_dbregex(self):
        """
        Test __dbregex__(qry, data)
        """
        self.assertEqual('TBD', 'TBD')

    def test_init_no_options_should_raise(self):
        """
        Test __init__(self, opts, init=False)
        """
        with self.assertRaises(TypeError) as cm:
            sfdb = SpiderFootDb(None, None)

        with self.assertRaises(ValueError) as cm:
            sfdb = SpiderFootDb(dict(), None)

    def test_init(self):
        """
        Test __init__(self, opts, init=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        self.assertIsInstance(sfdb, SpiderFootDb)
 
    @unittest.skip("todo")
    def test_create(self):
        """
        Test create(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.create()
        self.assertEqual('TBD', 'TBD')

    def test_close(self):
        """
        Test close(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.close()

    def test_search_should_return_a_list(self):
        """
        Test search(self, criteria, filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        search_results = sfdb.search(dict(), False)
        self.assertIsInstance(search_results, list)

        criteria = {
            'scan_id': None,
            'type': None,
            'value': None,
            'regex': None
        }

        search_results = sfdb.search(criteria, False)
        self.assertIsInstance(search_results, list)

    def test_event_types_should_return_a_list(self):
        """
        Test eventTypes(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        event_types = sfdb.eventTypes()
        self.assertIsInstance(event_types, list)

    @unittest.skip("todo")
    def test_scan_log_event(self):
        """
        Test scanLogEvent(self, instanceId, classification, message, component=None)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_instance(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_instance_set(self):
        """
        Test scanInstanceSet(self, instanceId, started=None, ended=None, status=None)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_instance_get_should_return_a_list(self):
        """
        Test scanInstanceGet(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        scan_instance = sfdb.scanInstanceGet(None)
        self.assertIsInstance(scan_instance, list)

    @unittest.skip("todo")
    def test_scan_result_summary(self):
        """
        Test scanResultSummary(self, instanceId, by="type")
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_result_event(self):
        """
        Test scanResultEvent(self, instanceId, eventType='ALL', filterFp=False)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_result_event_unique(self):
        """
        Test scanResultEventUnique(self, instanceId, eventType='ALL', filterFp=False)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_logs(self):
        """
        Test scanLogs(self, instanceId, limit=None, fromRowId=None, reverse=False)
        """
        self.assertEqual('TBD', 'TBD')

    def test_scan_errors(self):
        """
        Test scanErrors(self, instanceId, limit=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        scan_instance = sfdb.scanErrors(None, None)
        self.assertIsInstance(scan_instance, list)

    @unittest.skip("todo")
    def test_scan_instance_delete(self):
        """
        Test scanInstanceDelete(self, instanceId)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_results_update_fp(self):
        """
        Test scanResultsUpdateFP(self, instanceId, resultHashes, fpFlag)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_config_set(self):
        """
        Test configSet(self, optMap=dict())
        """
        self.assertEqual('TBD', 'TBD')

    def test_config_get_should_return_a_dict(self):
        """
        Test configGet(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        config = sfdb.configGet()
        self.assertIsInstance(config, dict)

    @unittest.skip("todo")
    def test_config_clear(self):
        """
        Test configClear(self)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_config_set(self):
        """
        Test scanConfigSet(self, id, optMap=dict())
        """
        self.assertEqual('TBD', 'TBD')

    def test_scan_config_get_should_return_a_dict(self):
        """
        Test scanConfigGet(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        scan_config = sfdb.scanConfigGet(None)
        self.assertIsInstance(scan_config, dict)

    @unittest.skip("todo")
    def test_scan_event_store(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_instance_list(self):
        """
        Test scanInstanceList(self)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_result_history(self):
        """
        Test scanResultHistory(self, instanceId)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_element_sources_direct(self):
        """
        Test scanElementSourcesDirect(self, instanceId, elementIdList)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_element_children_direct(self):
        """
        Test scanElementChildrenDirect(self, instanceId, elementIdList)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_element_sources_all(self):
        """
        Test scanElementSourcesAll(self, instanceId, childData)
        """
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_element_children_all(self):
        """
        Test scanElementChildrenAll(self, instanceId, parentIds)
        """
        self.assertEqual('TBD', 'TBD')

if __name__ == '__main__':
    unittest.main()

