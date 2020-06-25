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

        search_results = sfdb.search(None, None)
        self.assertIsInstance(search_results, list)
        self.assertFalse(search_results)

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
        self.assertFalse(search_results)

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
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.scanLogEvent(None, None, None, None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_instance_create(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.scanInstanceCreate(None, None, None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_instance_set(self):
        """
        Test scanInstanceSet(self, instanceId, started=None, ended=None, status=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        sfdb.scanInstanceSet(None, None, None, None)
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_instance_get_should_return_a_list(self):
        """
        Test scanInstanceGet(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_instance = 'example scan instance'
        scan_instance_get = sfdb.scanInstanceGet(scan_instance)
        self.assertIsInstance(scan_instance_get, list)
        self.assertIsIn(scan_instance, scan_instance_get)

        self.assertEqual('TBD', 'TBD')

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

    def test_scan_logs_should_return_a_list(self):
        """
        Test scanLogs(self, instanceId, limit=None, fromRowId=None, reverse=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        scan_logs = sfdb.scanLogs(None, None, None, None)
        self.assertIsInstance(scan_logs, list)

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
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.scanConfigDelete(None)

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
        sfdb = SpiderFootDb(self.default_options, False)
        config = sfdb.configClear()
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

    def test_scan_instance_list_should_return_a_list(self):
        """
        Test scanInstanceList(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_instances = sfdb.scanInstanceList()
        self.assertIsInstance(scan_instances, list)

    def test_scan_result_history_should_return_a_list(self):
        """
        Test scanResultHistory(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_result_history = sfdb.scanResultHistory(None)
        self.assertIsInstance(scan_result_history, list)

    @unittest.skip("todo")
    def test_scan_element_sources_direct_should_return_a_list(self):
        """
        Test scanElementSourcesDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_element_sources_direct = sfdb.scanElementSourcesDirect(None, None)
        self.assertIsInstance(scan_element_sources_direct, list)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_element_children_direct_should_return_a_list(self):
        """
        Test scanElementChildrenDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_element_children_direct = sfdb.scanElementChildrenDirect(None, None)
        self.assertIsInstance(scan_element_children_direct, list)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_element_sources_all_should_return_a_list(self):
        """
        Test scanElementSourcesAll(self, instanceId, childData)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_element_sources_all = sfdb.scanElementSourcesAll(None, None)
        self.assertIsInstance(scan_element_sources_all, list)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_element_children_all_should_return_a_list(self):
        """
        Test scanElementChildrenAll(self, instanceId, parentIds)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_element_children_all = sfdb.scanElementChildrenAll(None, None)
        self.assertIsInstance(scan_element_children_all, list)

        self.assertEqual('TBD', 'TBD')

if __name__ == '__main__':
    unittest.main()

