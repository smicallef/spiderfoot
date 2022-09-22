# test_spiderfootplugin.py
import pytest
import unittest

from sflib import SpiderFoot
from spiderfoot import SpiderFootDb, SpiderFootEvent, SpiderFootPlugin, SpiderFootTarget


@pytest.mark.usefixtures
class TestSpiderFootPlugin(unittest.TestCase):
    """
    Test SpiderFoot
    """

    def test_init(self):
        """
        Test __init__(self)
        """
        sfp = SpiderFootPlugin()
        self.assertIsInstance(sfp, SpiderFootPlugin)

    def test_updateSocket(self):
        """
        Test _updateSocket(self, sock)
        """
        sfp = SpiderFootPlugin()

        sfp._updateSocket(None)
        self.assertEqual('TBD', 'TBD')

    def test_clearListeners(self):
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

    def test_enrichTargetargument_target_should_enrih_target(self):
        """
        Test enrichTarget(self, target)
        """
        sfp = SpiderFootPlugin()

        sfp.enrichTarget(None)
        self.assertEqual('TBD', 'TBD')

    def test_setTarget_should_set_a_target(self):
        """
        Test setTarget(self, target)
        """
        sfp = SpiderFootPlugin()

        target = SpiderFootTarget("spiderfoot.net", "INTERNET_NAME")
        sfp.setTarget(target)

        get_target = sfp.getTarget().targetValue
        self.assertIsInstance(get_target, str)
        self.assertEqual("spiderfoot.net", get_target)

    def test_setTarget_argument_target_invalid_type_should_raise_TypeError(self):
        """
        Test setTarget(self, target)
        """
        sfp = SpiderFootPlugin()

        invalid_types = [None, "", list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfp.setTarget(invalid_type)

    def test_set_dbhargument_dbh_should_set_database_handle(self):
        """
        Test setDbh(self, dbh)
        """
        sfdb = SpiderFootDb(self.default_options, False)
        sfp = SpiderFootPlugin()

        sfp.setDbh(sfdb)
        self.assertIsInstance(sfp.__sfdb__, SpiderFootDb)

    def test_setScanId_argument_id_should_set_a_scan_id(self):
        """
        Test setScanId(self, id)
        """
        sfp = SpiderFootPlugin()

        scan_id = '1234'
        sfp.setScanId(scan_id)

        get_scan_id = sfp.getScanId()
        self.assertIsInstance(get_scan_id, str)
        self.assertEqual(scan_id, get_scan_id)

    def test_setScanId_argument_id_invalid_type_should_raise_TypeError(self):
        """
        Test setScanId(self, id)
        """
        sfp = SpiderFootPlugin()

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfp.setScanId(invalid_type)

    def test_getScanId_should_return_a_string(self):
        """
        Test getScanId(self)
        """
        sfp = SpiderFootPlugin()

        scan_id = 'example scan id'
        sfp.setScanId(scan_id)

        get_scan_id = sfp.getScanId()
        self.assertIsInstance(get_scan_id, str)
        self.assertEqual(scan_id, get_scan_id)

    def test_getScanId_unitialised_scanid_should_raise_TypeError(self):
        """
        Test getScanId(self)
        """
        sfp = SpiderFootPlugin()

        with self.assertRaises(TypeError):
            sfp.getScanId()

    def test_getTarget_should_return_a_string(self):
        """
        Test getTarget(self)
        """
        sfp = SpiderFootPlugin()

        target = SpiderFootTarget("spiderfoot.net", "INTERNET_NAME")
        sfp.setTarget(target)

        get_target = sfp.getTarget().targetValue
        self.assertIsInstance(get_target, str)
        self.assertEqual("spiderfoot.net", get_target)

    def test_getTarget_unitialised_target_should_raise(self):
        """
        Test getTarget(self)
        """
        sfp = SpiderFootPlugin()

        with self.assertRaises(TypeError):
            sfp.getTarget()

    def test_register_listener(self):
        """
        Test registerListener(self, listener)
        """
        sfp = SpiderFootPlugin()
        sfp.registerListener(None)

        self.assertEqual('TBD', 'TBD')

    def test_setOutputFilter_should_set_output_filter(self):
        """
        Test setOutputFilter(self, types)
        """
        sfp = SpiderFootPlugin()

        output_filter = "test filter"
        sfp.setOutputFilter("test filter")
        self.assertEqual(output_filter, sfp.__outputFilter__)

    def test_tempStorage_should_return_a_dict(self):
        """
        Test tempStorage(self)
        """
        sfp = SpiderFootPlugin()

        temp_storage = sfp.tempStorage()
        self.assertIsInstance(temp_storage, dict)

    def test_notifyListeners_should_notify_listener_modules(self):
        """
        Test notifyListeners(self, sfEvent)
        """
        sfp = SpiderFootPlugin()
        sfdb = SpiderFootDb(self.default_options, False)
        sfp.setDbh(sfdb)

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None
        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        sfp.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notifyListeners_output_filter_matched_should_notify_listener_modules(self):
        """
        Test notifyListeners(self, sfEvent)
        """
        sfp = SpiderFootPlugin()
        sfdb = SpiderFootDb(self.default_options, False)
        sfp.setDbh(sfdb)

        target = SpiderFootTarget("spiderfoot.net", "INTERNET_NAME")
        sfp.setTarget(target)

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'test event type'
        event_data = 'test data'
        module = 'test module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        sfp.__outputFilter__ = event_type

        sfp.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notifyListeners_output_filter_unmatched_should_not_notify_listener_modules(self):
        """
        Test notifyListeners(self, sfEvent)
        """
        sfp = SpiderFootPlugin()
        sfdb = SpiderFootDb(self.default_options, False)
        sfp.setDbh(sfdb)

        target = SpiderFootTarget("spiderfoot.net", "INTERNET_NAME")
        sfp.setTarget(target)

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'test event type'
        event_data = 'test data'
        module = 'test module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        sfp.__outputFilter__ = "example unmatched event type"

        sfp.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notifyListeners_event_type_and_data_same_as_source_event_source_event_should_story_only(self):
        """
        Test notifyListeners(self, sfEvent)
        """
        sfp = SpiderFootPlugin()
        sfdb = SpiderFootDb(self.default_options, False)
        sfp.setDbh(sfdb)

        event_type = 'ROOT'
        event_data = 'test data'
        module = 'test module'
        source_event = None
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'test event type'
        event_data = 'test data'
        module = 'test module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        sfp.notifyListeners(evt)

        self.assertEqual('TBD', 'TBD')

    def test_notifyListeners_argument_sfEvent_invalid_event_should_raise_TypeError(self):
        """
        Test notifyListeners(self, sfEvent)
        """
        sfp = SpiderFootPlugin()

        invalid_types = [None, "", list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfp.notifyListeners(invalid_type)

    def test_checkForStop(self):
        """
        Test checkForStop(self)
        """
        sfp = SpiderFootPlugin()

        class DatabaseStub:
            def scanInstanceGet(self, scanId):
                return [None, None, None, None, None, status]

        sfp.__sfdb__ = DatabaseStub()
        sfp.__scanId__ = 'example scan id'

        # pseudo-parameterized test
        scan_statuses = [
            (None, False),
            ("anything", False),
            ("RUNNING", False),
            ("ABORT-REQUESTED", True)
        ]
        for status, expectedReturnValue in scan_statuses:
            returnValue = sfp.checkForStop()
            self.assertEqual(returnValue, expectedReturnValue, status)

    def test_watchedEvents_should_return_a_list(self):
        """
        Test watchedEvents(self)
        """
        sfp = SpiderFootPlugin()

        watched_events = sfp.watchedEvents()
        self.assertIsInstance(watched_events, list)

    def test_producedEvents_should_return_a_list(self):
        """
        Test producedEvents(self)
        """
        sfp = SpiderFootPlugin()

        produced_events = sfp.producedEvents()
        self.assertIsInstance(produced_events, list)

    def test_handleEvent(self):
        """
        Test handleEvent(self, sfEvent)
        """
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        sfp = SpiderFootPlugin()
        sfp.handleEvent(evt)

    def test_start(self):
        """
        Test start(self)
        """
        sf = SpiderFoot(self.default_options)
        sfp = SpiderFootPlugin()
        sfp.sf = sf

        sfp.start()
