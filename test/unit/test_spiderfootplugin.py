# test_spiderfootplugin.py
import sflib
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent, SpiderFootTarget
from sfdb import SpiderFootDb
import unittest

class TestSpiderFootPlugin(unittest.TestCase):
    """
    Test SpiderFoot
    """

    default_options = {
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

    def test_init(self):
        """
        Test __init__(self)
        """
        sfp = SpiderFootPlugin()
        self.assertIsInstance(sfp, SpiderFootPlugin)

    def test_update_socket(self):
        """
        Test _updateSocket(self, sock)
        """
        sfp = SpiderFootPlugin()

        sfp._updateSocket(None)
        self.assertEqual('TBD', 'TBD')

    def test_clear_listeners(self):
        """
        Test clearListeners(self)
        """
        sfp = SpiderFootPlugin()

        sfp.clearListeners()
        self.assertEqual('TBD', 'TBD')

    def test_setup(self):
        """
        Test setup(self, sf, userOpts=dict())
        """
        sfp = SpiderFootPlugin()

        sfp.setup(None)
        sfp.setup(None, None)
        self.assertEqual('TBD', 'TBD')

    def test_enrich_target(self):
        """
        Test enrichTarget(self, target)
        """
        sfp = SpiderFootPlugin()

        sfp.enrichTarget(None)
        self.assertEqual('TBD', 'TBD')

    def test_set_target_should_set_a_target(self):
        """
        Test setTarget(self, target)
        """
        sfp = SpiderFootPlugin()

        target = SpiderFootTarget("spiderfoot.net", "INTERNET_NAME")
        sfp.setTarget(target)

        get_target = sfp.getTarget().targetValue
        self.assertIsInstance(get_target, str)
        self.assertEqual("spiderfoot.net", get_target)

    def test_set_target_invalid_target_should_raise(self):
        """
        Test setTarget(self, target)
        """
        sfp = SpiderFootPlugin()

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    sfp.setTarget(invalid_type)

    def test_set_dbh(self):
        """
        Test setDbh(self, dbh)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfp = SpiderFootPlugin()

        sfp.setDbh(sfdb)
        self.assertIsInstance(sfp.__sfdb__, SpiderFootDb)

    def test_set_scan_id_should_set_a_scan_id(self):
        """
        Test setScanId(self, id)
        """
        sfp = SpiderFootPlugin()

        scan_id = '1234'
        sfp.setScanId(scan_id)

        get_scan_id = sfp.getScanId()
        self.assertIsInstance(get_scan_id, str)
        self.assertEqual(scan_id, get_scan_id)

    def test_get_scan_id_should_return_a_string(self):
        """
        Test getScanId(self)
        """
        sfp = SpiderFootPlugin()

        scan_id = 'example scan id'
        sfp.setScanId(scan_id)

        get_scan_id = sfp.getScanId()
        self.assertEqual(str, type(get_scan_id))
        self.assertEqual(scan_id, get_scan_id)

    def test_get_scan_id_unitialised_scanid_should_raise(self):
        """
        Test getScanId(self)
        """
        sfp = SpiderFootPlugin()

        with self.assertRaises(TypeError) as cm:
            scan_id = sfp.getScanId()

    def test_get_target_should_return_a_string(self):
        """
        Test getTarget(self)
        """
        sfp = SpiderFootPlugin()

        target = SpiderFootTarget("spiderfoot.net", "INTERNET_NAME")
        sfp.setTarget(target)

        get_target = sfp.getTarget().targetValue
        self.assertIsInstance(get_target, str)
        self.assertEqual("spiderfoot.net", get_target)

    def test_get_target_unitialised_target_should_raise(self):
        """
        Test getTarget(self)
        """
        sfp = SpiderFootPlugin()

        with self.assertRaises(TypeError) as cm:
            get_target = sfp.getTarget()

    def test_register_listener(self):
        """
        Test registerListener(self, listener)
        """
        sfp = SpiderFootPlugin()
        sfp.registerListener(None)

        self.assertEqual('TBD', 'TBD')

    def test_set_output_filter_should_set_output_filter(self):
        """
        Test setOutputFilter(self, types)
        """
        sfp = SpiderFootPlugin()

        output_filter = "test filter"
        sfp.setOutputFilter("test filter")
        self.assertEqual(output_filter, sfp.__outputFilter__)

    def test_temp_storage_should_return_a_dict(self):
        """
        Test tempStorage(self)
        """
        sfp = SpiderFootPlugin()

        temp_storage = sfp.tempStorage()
        self.assertEqual(dict, type(temp_storage))

    def test_notify_listeners(self):
        """
        Test notifyListeners(self, sfEvent)

        Todo:
            Test with source event
        """
        sfp = SpiderFootPlugin()

        class DatabaseStub:
            def scanInstanceGet(self, scanId):
                return [None, None, None, None, None, None]

        sfp.__sfdb__ = DatabaseStub()

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None #SpiderFootEvent("ROOT", '', '', "ROOT")
        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        sfp.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notify_listeners_invalid_event_should_raise(self):
        """
        Test notifyListeners(self, sfEvent)
        """
        sfp = SpiderFootPlugin()

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    sfp.notifyListeners(None)

    def test_check_for_stop(self):
        """
        Test checkForStop(self)

        Todo:
            include other statuses for completeness
        """
        sfp = SpiderFootPlugin()

        class DatabaseStub:
            def scanInstanceGet(self, scanId):
                return [None, None, None, None, None, status]

        sfp.__sfdb__ = DatabaseStub()
        sfp.__scanId__ = 'example scan id'

        # pseudo-parameterized test
        for status, expectedReturnValue in [("RUNNING", False), ("ABORT-REQUESTED", True)]:
            returnValue = sfp.checkForStop()
            self.assertEqual(returnValue, expectedReturnValue, status)

    def test_watched_events_should_return_a_list(self):
        """
        Test watchedEvents(self)
        """
        sfp = SpiderFootPlugin()

        watched_events = sfp.watchedEvents()
        self.assertIsInstance(watched_events, list)

    def test_produced_events_should_return_a_list(self):
        """
        Test producedEvents(self)
        """
        sfp = SpiderFootPlugin()

        produced_events = sfp.producedEvents()
        self.assertIsInstance(produced_events, list)

    def test_handle_event(self):
        """
        Test handleEvent(self, sfEvent)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        sfp = SpiderFootPlugin()
        sfp.handleEvent(evt)

    def test_start(self):
        """
        Test start(self)
        """
        sfp = SpiderFootPlugin()

        sfp.start()

if __name__ == '__main__':
    unittest.main()

