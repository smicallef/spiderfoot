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

    def test_setup(self):
        """
        Test setup(self, sf, userOpts=dict())
        """
        sfp = SpiderFootPlugin()

        sfp.setup(None)
        self.assertEqual('TBD', 'TBD')

    def test_enrich_target(self):
        """
        Test enrichTarget(self, target)
        """
        sfp = SpiderFootPlugin()

        sfp.enrichTarget(None)
        self.assertEqual('TBD', 'TBD')

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

    def test_get_scan_id(self):
        """
        Test getScanId(self)
        """
        sfp = SpiderFootPlugin()

        sfp.getScanId()
        self.assertEqual('TBD', 'TBD')

    def test_get_target(self):
        """
        Test getTarget(self)
        """
        sfp = SpiderFootPlugin()

        sfp.getTarget()
        self.assertEqual('TBD', 'TBD')

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

    def test_check_for_stop_should_return_a_boolean(self):
        """
        Test checkForStop(self)
        """
        sfp = SpiderFootPlugin()

        check_for_stop = sfp.checkForStop()
        self.assertEqual(False, check_for_stop)

    def test_default_opts_should_return_a_dict(self):
        """
        Test defaultOpts(self)
        Note: this function is not currently used
        """
        sfp = SpiderFootPlugin()

        default_opts = sfp.defaultOpts()
        self.assertEqual(dict, type(default_opts))

    def test_watched_events_should_return_a_list(self):
        """
        Test watchedEvents(self)
        """
        sfp = SpiderFootPlugin()

        watched_events = sfp.watchedEvents()
        self.assertEqual(list, type(watched_events))

    def test_produced_events_should_return_a_list(self):
        """
        Test producedEvents(self)
        """
        sfp = SpiderFootPlugin()

        produced_events = sfp.watchedEvents()
        self.assertEqual(list, type(produced_events))

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
        self.assertEqual('TBD', 'TBD')

    def test_start(self):
        """
        Test start(self)
        """
        sfp = SpiderFootPlugin()

        sfp.start()
        self.assertEqual('TBD', 'TBD')

if __name__ == '__main__':
    unittest.main()

