# test_spiderfootevent.py
from sflib import SpiderFootEvent
import unittest

class TestSpiderFootEvent(unittest.TestCase):
    """
    Test SpiderFootEvent
    """

    def test_init_root_event(self):
        """
        Test __init__(self, eventType, data, module, sourceEvent, confidence=100, visibility=100, risk=0)
        """
        event_data = ''
        module = ''
        source_event = ''

        event_type = 'ROOT'
        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        self.assertIsInstance(evt, SpiderFootEvent)

    def test_init_nonroot_event_with_root_source_event(self):
        """
        Test __init__(self, eventType, data, module, sourceEvent, confidence=100, visibility=100, risk=0)
        """
        event_data = ''
        module = ''
        source_event = ''

        event_type = 'ROOT'
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example non-root event type'
        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        self.assertIsInstance(evt, SpiderFootEvent)

    def test_init_invalid_event_data_type_should_exit(self):
        """
        Test __init__(self, eventType, data, module, sourceEvent, confidence=100, visibility=100, risk=0)
        """
        event_type = 'ROOT'
        module = ''
        source_event = ''

        with self.assertRaises(SystemExit) as cm:
            event_data = int(1)
            evt = SpiderFootEvent(event_type, event_data, module, source_event)

        self.assertEqual(cm.exception.code, -1)

    def test_init_nonroot_event_type_with_no_source_event_should_exit(self):
        """
        Test __init__(self, eventType, data, module, sourceEvent, confidence=100, visibility=100, risk=0)
        """
        event_data = ''
        module = ''

        with self.assertRaises(SystemExit) as cm:
            event_type = 'example non-root event type'
            source_event = ''
            evt = SpiderFootEvent(event_type, event_data, module, source_event)

        self.assertEqual(cm.exception.code, -1)

    def test_asdict_root_event_should_return_a_dict(self):
        """
        Test asDict(self)
        """
        event_data = ''
        module = ''
        source_event = ''

        event_type = 'ROOT'
        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt_dict = evt.asDict()

        self.assertIsInstance(evt_dict, dict)

    def test_asdict_nonroot_event_should_return_a_dict(self):
        """
        Test asDict(self)
        """
        event_data = ''
        module = ''
        source_event = ''

        event_type = 'ROOT'
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example non-root event type'
        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt_dict = evt.asDict()

        self.assertIsInstance(evt_dict, dict)

    def test_get_hash_root_event_should_return_root_as_a_string(self):
        """
        Test getHash(self)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''

        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt_hash = evt.getHash()

        self.assertEqual('ROOT', evt_hash)

    def test_get_hash_nonroot_event_should_return_a_string(self):
        """
        Test getHash(self)
        """
        event_type = 'not ROOT'
        event_data = ''
        module = ''
        source_event = SpiderFootEvent("ROOT", '', '', "ROOT")

        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt_hash = evt.getHash()

        self.assertIsInstance(evt_hash, str)

    @unittest.skip("unused function")
    def test_set_confidence(self):
        """
        Test setConfidence(self, confidence)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''

        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt.setConfidence('confidence')

    @unittest.skip("unused function")
    def test_set_visibility(self):
        """
        Test setVisibility(self, visibility)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''

        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt.setVisibility('visibility')

    @unittest.skip("unused function")
    def test_set_risk(self):
        """
        Test setRisk(self, risk)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''

        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt.setRisk('risk')

    @unittest.skip("unused function")
    def test_set_source_event_hash(self):
        """
        Test setSourceEventHash(self, srcHash)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''

        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt.setSourceEventHash('source event hash')

if __name__ == '__main__':
    unittest.main()

