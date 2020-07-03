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

    def test_init_invalid_event_data_type_should_raise(self):
        """
        Test __init__(self, eventType, data, module, sourceEvent, confidence=100, visibility=100, risk=0)
        """
        event_type = 'ROOT'
        module = ''
        source_event = ''

        invalid_types = [None, list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    evt = SpiderFootEvent(event_type, invalid_type, module, source_event)

    def test_init_invalid_source_event_type_should_raise(self):
        """
        Test __init__(self, eventType, data, module, sourceEvent, confidence=100, visibility=100, risk=0)
        """
        event_data = 'example event data'
        module = ''
        event_type = 'example non-root event type'

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    evt = SpiderFootEvent(event_type, event_data, module, invalid_type)

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

    def test_set_confidence_invalid_confidence_should_raise(self):
        """
        Test setConfidence(self, confidence)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    evt.setConfidence(invalid_type)

        with self.assertRaises(ValueError) as cm:
            evt.setConfidence(-1)
        with self.assertRaises(ValueError) as cm:
            evt.setConfidence(101)

    def test_set_confidence_should_set_confidence_attribute(self):
        """
        Test setConfidence(self, confidence)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        confidence = 100
        evt.setConfidence(confidence)
        self.assertEqual(confidence, evt.confidence)

    def test_set_visibility_invalid_visibility_should_raise(self):
        """
        Test setVisibility(self, visibility)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    evt.setVisibility(invalid_type)

        with self.assertRaises(ValueError) as cm:
            evt.setVisibility(-1)
        with self.assertRaises(ValueError) as cm:
            evt.setVisibility(101)

    def test_set_visibility_should_set_visibility_attribute(self):
        """
        Test setVisibility(self, visibility)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        visibility = 100
        evt.setVisibility(visibility)
        self.assertEqual(visibility, evt.visibility)

    def test_set_risk_invalid_risk_should_raise(self):
        """
        Test setRisk(self, risk)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError) as cm:
                    evt.setRisk(invalid_type)

        with self.assertRaises(ValueError) as cm:
            evt.setRisk(-1)
        with self.assertRaises(ValueError) as cm:
            evt.setRisk(101)

    def test_set_risk_should_set_risk_attribute(self):
        """
        Test setRisk(self, risk)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        risk = 100
        evt.setRisk(risk)
        self.assertEqual(risk, evt.risk)

    def test_set_source_event_hash_should_set_source_event_hash_attribute(self):
        """
        Test setSourceEventHash(self, srcHash)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        source_event_hash = 'source event hash'
        evt.setSourceEventHash(source_event_hash)
        self.assertEqual(source_event_hash, evt.sourceEventHash)

if __name__ == '__main__':
    unittest.main()

