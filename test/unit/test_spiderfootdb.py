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

    def test_init_invalid_args_should_raise(self):
        """
        Test __init__(self, opts, init=False)
        """
        with self.assertRaises(TypeError) as cm:
            sfdb = SpiderFootDb(None)

        with self.assertRaises(TypeError) as cm:
            sfdb = SpiderFootDb([])

    def test_init_no_options_should_raise(self):
        """
        Test __init__(self, opts, init=False)
        """
        with self.assertRaises(ValueError) as cm:
            sfdb = SpiderFootDb(dict())

        with self.assertRaises(ValueError) as cm:
            opts = dict()
            opts['example'] = 'example not-empty dict'
            sfdb = SpiderFootDb(opts)

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

        criteria = {
            'scan_id': "",
            'type': "",
            'value': "",
            'regex': ""
        }

        search_results = sfdb.search(criteria, False)
        self.assertIsInstance(search_results, list)
        self.assertFalse(search_results)

    def test_search_invalid_criteria_should_raise(self):
        """
        Test search(self, criteria, filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, "", list()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    search_results = sfdb.search(invalid_type, False)

        criteria = {
            'scan_id': None,
            'type': None,
            'value': None,
            'regex': None
        }

        with self.assertRaises(ValueError) as cm:
            search_results = sfdb.search(criteria, False)

    def test_event_types_should_return_a_list(self):
        """
        Test eventTypes(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        event_types = sfdb.eventTypes()
        self.assertIsInstance(event_types, list)

    def test_scan_log_event(self):
        """
        Test scanLogEvent(self, instanceId, classification, message, component=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.scanLogEvent("", "", "", None)

    def test_scan_log_event_invalid_instance_id_should_raise(self):
        """
        Test scanLogEvent(self, instanceId, classification, message, component=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    sfdb.scanLogEvent(invalid_type, "", "")

    def test_scan_log_event_invalid_classification_should_raise(self):
        """
        Test scanLogEvent(self, instanceId, classification, message, component=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    sfdb.scanLogEvent(instance_id, invalid_type, "")

    def test_scan_log_event_invalid_message_should_raise(self):
        """
        Test scanLogEvent(self, instanceId, classification, message, component=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    sfdb.scanLogEvent(instance_id, "", invalid_type)

    @unittest.skip("todo")
    def test_scan_instance_create(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfdb.scanInstanceCreate(None, None, None)

        self.assertEqual('TBD', 'TBD')

    def test_scan_instance_create_invalid_instanceid_should_raise(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_name = ""
        scan_target = "spiderfoot.net"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    sfdb.scanInstanceCreate(invalid_type, scan_name, scan_target)

    def test_scan_instance_create_invalid_scan_name_should_raise(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_target = "spiderfoot.net"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    sfdb.scanInstanceCreate(instance_id, invalid_type, scan_target)

    def test_scan_instance_create_invalid_scan_target_should_raise(self):
        """
        Test scanInstanceCreate(self, instanceId, scanName, scanTarget)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_name = ""
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    sfdb.scanInstanceCreate(instance_id, scan_name, invalid_type)

    def test_scan_instance_set(self):
        """
        Test scanInstanceSet(self, instanceId, started=None, ended=None, status=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_instance = 'example scan instance'
        sfdb.scanInstanceSet(scan_instance, None, None, None)
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_instance_get_should_return_a_list(self):
        """
        Test scanInstanceGet(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        scan_instance = 'example scan instance'
        sfdb.scanInstanceSet(scan_instance, None, None, None)

        scan_instance_get = sfdb.scanInstanceGet(scan_instance)
        self.assertIsInstance(scan_instance_get, list)

    def test_scan_result_summary_should_return_a_list(self):
        """
        Test scanResultSummary(self, instanceId, by="type")
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_results_summary = sfdb.scanResultSummary(instance_id, "type")
        self.assertIsInstance(scan_results_summary, list)

    def test_scan_result_summary_invalid_type_should_raise(self):
        """
        Test scanResultSummary(self, instanceId, by="type")
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    scan_results_summary = sfdb.scanResultSummary(invalid_type)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    scan_results_summary = sfdb.scanResultSummary(instance_id, None)

        with self.assertRaises(ValueError) as cm:
            scan_results_summary = sfdb.scanResultSummary(instance_id, "invalid filter type")

    def test_scan_result_event_should_return_a_list(self):
        """
        Test scanResultEvent(self, instanceId, eventType='ALL', filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_result_event = sfdb.scanResultEvent(instance_id, "", False)
        self.assertIsInstance(scan_result_event, list)

    def test_scan_result_event_invalid_event_type_should_raise(self):
        """
        Test scanResultEvent(self, instanceId, eventType='ALL', filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    scan_result_event = sfdb.scanResultEvent(instance_id, invalid_type, None)

    def test_scan_result_event_unique_should_return_a_list(self):
        """
        Test scanResultEventUnique(self, instanceId, eventType='ALL', filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_result_event = sfdb.scanResultEventUnique(instance_id, "", False)
        self.assertIsInstance(scan_result_event, list)

    def test_scan_result_event_unique_invalid_event_type_should_raise(self):
        """
        Test scanResultEventUnique(self, instanceId, eventType='ALL', filterFp=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    scan_result_event = sfdb.scanResultEventUnique(instance_id, invalid_type, None)

    def test_scan_logs_should_return_a_list(self):
        """
        Test scanLogs(self, instanceId, limit=None, fromRowId=None, reverse=False)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_logs = sfdb.scanLogs(instance_id, None, None, None)
        self.assertIsInstance(scan_logs, list)

        self.assertEqual('TBD', 'TBD')

    def test_scan_errors(self):
        """
        Test scanErrors(self, instanceId, limit=None)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        instance_id = "example instance id"
        scan_instance = sfdb.scanErrors(instance_id, None)
        self.assertIsInstance(scan_instance, list)

    def test_scan_instance_delete(self):
        """
        Test scanInstanceDelete(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        instance_id = "example instance id"
        scan_instance_delete = sfdb.scanInstanceDelete(instance_id)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_scan_results_update_fp(self):
        """
        Test scanResultsUpdateFP(self, instanceId, resultHashes, fpFlag)
        """
        instance_id = "example instance id"
        self.assertEqual('TBD', 'TBD')

    def test_config_set_should_set_config_opts(self):
        """
        Test configSet(self, optMap=dict())
        """
        sfdb = SpiderFootDb(self.default_options, False)
        opts = dict()
        opts['example'] = 'example non-default config opt'
        sfdb.configSet(opts)

        config = sfdb.configGet()
        self.assertIsInstance(config, dict)
        self.assertIn('example', config)

    def test_config_set_invalid_optmap_should_raise(self):
        """
        Test configSet(self, optMap=dict())
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, "", list()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    scan_result_event = sfdb.scanResultEventUnique("", invalid_type, None)
                    sfdb.configSet(invalid_type)

        with self.assertRaises(ValueError) as cm:
            sfdb.configSet(dict())

    def test_config_get_should_return_a_dict(self):
        """
        Test configGet(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        config = sfdb.configGet()
        self.assertIsInstance(config, dict)

    def test_config_clear_should_clear_config(self):
        """
        Test configClear(self)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        opts = dict()
        opts['example'] = 'example non-default config opt'
        sfdb.configSet(opts)

        config = sfdb.configGet()
        self.assertIsInstance(config, dict)
        self.assertIn('example', config)

        sfdb.configClear()

        config = sfdb.configGet()
        self.assertIsInstance(config, dict)
        self.assertNotIn('example', config)

    def test_scan_config_set(self):
        """
        Test scanConfigSet(self, id, optMap=dict())
        """
        sfdb = SpiderFootDb(self.default_options, False)

        invalid_types = [None, ""]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    sfdb.scanConfigSet("", invalid_type)

        with self.assertRaises(ValueError) as cm:
            sfdb.scanConfigSet("", dict())

    def test_scan_config_get_should_return_a_dict(self):
        """
        Test scanConfigGet(self, instanceId)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_config = sfdb.scanConfigGet(instance_id)
        self.assertIsInstance(scan_config, dict)

    def test_scan_event_store_invalid_instanceid_should_raise(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        event = ""
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    sfdb.scanEventStore(invalid_type, event)

        with self.assertRaises(ValueError) as cm:
            sfdb.scanEventStore("", event)

    def test_scan_event_store_invalid_event_should_raise(self):
        """
        Test scanEventStore(self, instanceId, sfEvent, truncateSize=0)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    sfdb.scanEventStore(instance_id, invalid_type)

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

        instance_id = "example instance id"
        scan_result_history = sfdb.scanResultHistory(instance_id)
        self.assertIsInstance(scan_result_history, list)

    def test_scan_element_sources_direct_should_return_a_list(self):
        """
        Test scanElementSourcesDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        element_id_list = []
        scan_element_sources_direct = sfdb.scanElementSourcesDirect(instance_id, element_id_list)
        self.assertIsInstance(scan_element_sources_direct, list)

        self.assertEqual('TBD', 'TBD')

    def test_scan_element_sources_direct_invalid_instanceid_should_raise(self):
        """
        Test scanElementSourcesDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        element_id_list = []
        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    scan_element_sources_direct = sfdb.scanElementSourcesDirect(invalid_type, element_id_list)

    def test_scan_element_children_direct_should_return_a_list(self):
        """
        Test scanElementChildrenDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_element_children_direct = sfdb.scanElementChildrenDirect(instance_id, list())
        self.assertIsInstance(scan_element_children_direct, list)

        self.assertEqual('TBD', 'TBD')

    def test_scan_element_children_direct_invalid_element_id_list_should_raise(self):
        """
        Test scanElementChildrenDirect(self, instanceId, elementIdList)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, "", dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    scan_element_children_direct = sfdb.scanElementChildrenDirect(instance_id, invalid_type)

    @unittest.skip("todo")
    def test_scan_element_sources_all_should_return_a_list(self):
        """
        Test scanElementSourcesAll(self, instanceId, childData)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        child_data = []
        scan_element_sources_all = sfdb.scanElementSourcesAll(instance_id, child_data)
        self.assertIsInstance(scan_element_sources_all, list)

        self.assertEqual('TBD', 'TBD')

    def test_scan_element_sources_all_invalid_child_data_should_raise(self):
        """
        Test scanElementSourcesAll(self, instanceId, childData)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, "", dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    scan_element_sources_all = sfdb.scanElementSourcesAll(instance_id, invalid_type)

        with self.assertRaises(ValueError) as cm:
            scan_element_sources_all = sfdb.scanElementSourcesAll(instance_id, list())

    def test_scan_element_children_all_should_return_a_list(self):
        """
        Test scanElementChildrenAll(self, instanceId, parentIds)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        scan_element_children_all = sfdb.scanElementChildrenAll(instance_id, list())
        self.assertIsInstance(scan_element_children_all, list)

        self.assertEqual('TBD', 'TBD')

    def test_scan_element_children_all_invalid_element_id_list_should_raise(self):
        """
        Test scanElementChildrenAll(self, instanceId, parentIds)
        """
        sfdb = SpiderFootDb(self.default_options, False)

        instance_id = "example instance id"
        invalid_types = [None, "", dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    scan_element_children_all = sfdb.scanElementChildrenAll(instance_id, invalid_type)

if __name__ == '__main__':
    unittest.main()

