# test_spiderfootplugin.py
import sflib
from sflib import SpiderFootPlugin, SpiderFootEvent
import unittest

class TestSpiderFootPlugin(unittest.TestCase):
    """
    Test SpiderFoot
    """

    def test_init(self):
        """
        Test __init__(self)
        """
        sfp = SpiderFootPlugin()
        self.assertEqual(SpiderFootPlugin, type(sfp))

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

    @unittest.skip("overridden function")
    def test_setup(self):
        """
        Test setup(self, sf, userOpts=dict())
        """
        sfp = SpiderFootPlugin()

        sfp.setup(None)

    @unittest.skip("overridden function")
    def test_enrich_target(self):
        """
        Test enrichTarget(self, target)
        """
        sfp = SpiderFootPlugin()

        sfp.enrichTarget(None)

    def test_set_target(self):
        """
        Test setTarget(self, target)
        """
        sfp = SpiderFootPlugin()

        sfp.setTarget(None)
        self.assertEqual('TBD', 'TBD')

    def test_set_dbh(self):
        """
        Test setDbh(self, dbh)
        """
        sfp = SpiderFootPlugin()

        sfp.setDbh(None)
        self.assertEqual('TBD', 'TBD')

    def test_set_scan_id(self):
        """
        Test setScanId(self, id)
        """
        sfp = SpiderFootPlugin()

        sfp.setScanId(None)
        self.assertEqual('TBD', 'TBD')

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

    def test_get_target_should_return_a_string(self):
        """
        Test getTarget(self)
        """
        sfp = SpiderFootPlugin()

        target = 'spiderfoot.net'
        sfp.setTarget(target)

        get_target = sfp.getTarget()
        self.assertEqual(str, type(get_target))
        self.assertEqual(target, get_target)

    def test_get_target_invalid_target_should_exit(self):
        """
        Test getTarget(self)
        """
        sfp = SpiderFootPlugin()

        with self.assertRaises(SystemExit) as cm:
            sfp.getTarget()

        self.assertEqual(cm.exception.code, -1)

    def test_register_listener(self):
        """
        Test registerListener(self, listener)
        """
        self.assertEqual('TBD', 'TBD')

    def test_set_output_filter(self):
        """
        Test setOutputFilter(self, types)
        """
        self.assertEqual('TBD', 'TBD')

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
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        sfp = SpiderFootPlugin()
        sfp.notifyListeners(evt)
        self.assertEqual('TBD', 'TBD')

    def test_check_for_stop(self):
        """
        Test checkForStop(self)
        """
        sfp = SpiderFootPlugin()

        class DatabaseStub:
            def scanInstanceGet(self, scanId):
                return [None, None, None, None, None, status]

        sfp.__sfdb__ = DatabaseStub()

        # pseudo-parameterized test
        # TODO could include other statuses for completeness
        for status, expectedReturnValue in [("RUNNING", False), ("ABORT-REQUESTED", True)]:
            returnValue = sfp.checkForStop()
            self.assertEqual(returnValue, expectedReturnValue, status)

    @unittest.skip("unused function")
    def test_default_opts_should_return_a_dict(self):
        """
        Test defaultOpts(self)
        """
        sfp = SpiderFootPlugin()

        default_opts = sfp.defaultOpts()
        self.assertEqual(dict, type(default_opts))

    @unittest.skip("overridden function")
    def test_watched_events_should_return_a_list(self):
        """
        Test watchedEvents(self)
        """
        sfp = SpiderFootPlugin()

        watched_events = sfp.watchedEvents()
        self.assertEqual(list, type(watched_events))

    @unittest.skip("overridden function")
    def test_produced_events_should_return_a_list(self):
        """
        Test producedEvents(self)
        """
        sfp = SpiderFootPlugin()

        produced_events = sfp.producedEvents()
        self.assertEqual(list, type(produced_events))

    @unittest.skip("overridden function")
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

    @unittest.skip("overridden function")
    def test_start(self):
        """
        Test start(self)
        """
        sfp = SpiderFootPlugin()

        sfp.start()

if __name__ == '__main__':
    unittest.main()

