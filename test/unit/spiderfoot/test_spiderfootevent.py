# test_spiderfootevent.py
import unittest

from spiderfoot import SpiderFootEvent


class TestSpiderFootEvent(unittest.TestCase):

    def test_init_root_event_should_create_event(self):
        event_data = 'example event data'
        module = 'example module'
        source_event = ''

        event_type = 'ROOT'
        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        self.assertIsInstance(evt, SpiderFootEvent)

    def test_init_nonroot_event_with_root_sourceEvent_should_create_event(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example non-root event type'
        event_data = 'example event data'
        module = 'example module'
        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        self.assertIsInstance(evt, SpiderFootEvent)

    def test_init_argument_eventType_of_invalid_type_should_raise_TypeError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        module = 'example module'

        invalid_types = [None, bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootEvent(invalid_type, event_data, module, source_event)

    def test_init_argument_eventType_with_empty_value_should_raise_ValueError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = ''
        module = 'example module'

        with self.assertRaises(ValueError):
            SpiderFootEvent(event_type, event_data, module, source_event)

    def test_init_argument_data_of_invalid_type_should_raise_TypeError(self):
        event_type = 'ROOT'
        module = ''
        source_event = ''

        invalid_types = [None, bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootEvent(event_type, invalid_type, module, source_event)

    def test_init_argument_data_with_empty_value_should_raise_ValueError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = ''
        module = 'example module'

        with self.assertRaises(ValueError):
            SpiderFootEvent(event_type, event_data, module, source_event)

    def test_init_argument_module_of_invalid_type_should_raise_TypeError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = SpiderFootEvent(event_type, event_data, module, "ROOT")

        event_type = 'example non-root event type'
        invalid_types = [None, bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootEvent(event_type, event_data, invalid_type, source_event)

    def test_init_argument_module_with_empty_value_should_raise_ValueError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example event type'
        event_data = 'example event data'
        module = ''

        with self.assertRaises(ValueError):
            SpiderFootEvent(event_type, event_data, module, source_event)

    def test_init_argument_sourceEvent_of_invalid_type_should_raise_TypeError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''

        event_type = 'example non-root event type'
        module = 'example module'
        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootEvent(event_type, event_data, module, invalid_type)

    def test_init_argument_confidence_of_invalid_type_should_raise_TypeError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    evt = SpiderFootEvent(event_type, event_data, module, source_event)
                    evt.confidence = invalid_type

    def test_init_argument_confidence_invalid_value_should_raise_ValueError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''

        invalid_values = [-1, 101]
        for invalid_value in invalid_values:
            with self.subTest(invalid_value=invalid_value):
                with self.assertRaises(ValueError):
                    evt = SpiderFootEvent(event_type, event_data, module, source_event)
                    evt.confidence = invalid_value

    def test_init_argument_visibility_of_invalid_type_should_raise_TypeError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    evt = SpiderFootEvent(event_type, event_data, module, source_event)
                    evt.visibility = invalid_type

    def test_init_argument_visibility_invalid_value_should_raise_ValueError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''

        invalid_values = [-1, 101]
        for invalid_value in invalid_values:
            with self.subTest(invalid_value=invalid_value):
                with self.assertRaises(ValueError):
                    evt = SpiderFootEvent(event_type, event_data, module, source_event)
                    evt.visibility = invalid_value

    def test_init_argument_risk_of_invalid_type_should_raise_TypeError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    evt = SpiderFootEvent(event_type, event_data, module, source_event)
                    evt.risk = invalid_type

    def test_init_argument_risk_invalid_value_should_raise_ValueError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''

        invalid_values = [-1, 101]
        for invalid_value in invalid_values:
            with self.subTest(invalid_value=invalid_value):
                with self.assertRaises(ValueError):
                    evt = SpiderFootEvent(event_type, event_data, module, source_event)
                    evt.risk = invalid_value

    def test_confidence_attribute_should_return_confidence_as_integer(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        confidence = 100

        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt.confidence = confidence

        self.assertEqual(confidence, evt.confidence)

    def test_confidence_attribute_setter_invalid_type_should_raise_TypeError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    evt.confidence = invalid_type

    def test_visibility_attribute_should_return_visibility_as_integer(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        visibility = 100

        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt.visibility = visibility

        self.assertEqual(visibility, evt.visibility)

    def test_visibility_attribute_setter_invalid_type_should_raise_TypeError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    evt.visibility = invalid_type

    def test_risk_attribute_should_return_risk_as_integer(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        risk = 100

        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt.risk = risk

        self.assertEqual(risk, evt.risk)

    def test_risk_attribute_setter_invalid_type_should_raise_TypeError(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    evt.risk = invalid_type

    def test_actualSource_attribute_should_return_actual_source_as_string(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        actual_source = 'example actual source'
        evt.actualSource = actual_source

        self.assertEqual(actual_source, evt.actualSource)

    def test_sourceEventHash_attribute_should_return_source_event_hash_as_string(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        self.assertEqual("ROOT", evt.sourceEventHash)

    def test_moduleDataSource_attribute_should_return_module_data_source_as_string(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, module, source_event)

        module_data_source = 'example module data source'
        evt.moduleDataSource = module_data_source

        self.assertEqual(module_data_source, evt.moduleDataSource)

    def test_asdict_root_event_should_return_event_as_a_dict(self):
        event_data = 'example event data'
        module = 'example module data'
        source_event = ''

        event_type = 'ROOT'
        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt_dict = evt.asDict()

        self.assertIsInstance(evt_dict, dict)
        self.assertEqual(evt_dict['type'], event_type)
        self.assertEqual(evt_dict['data'], event_data)
        self.assertEqual(evt_dict['module'], module)

    def test_asdict_nonroot_event_should_return_event_as_a_dict(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''
        source_event = SpiderFootEvent(event_type, event_data, module, source_event)

        event_type = 'example non-root event type'
        event_data = 'example event data'
        module = 'example_module'
        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt_dict = evt.asDict()

        self.assertIsInstance(evt_dict, dict)
        self.assertEqual(evt_dict['type'], event_type)
        self.assertEqual(evt_dict['data'], event_data)
        self.assertEqual(evt_dict['module'], module)

    def test_hash_attribute_root_event_should_return_root_as_a_string(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = ''
        source_event = ''

        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt_hash = evt.hash

        self.assertEqual('ROOT', evt_hash)

    def test_hash_attribute_nonroot_event_should_return_a_string(self):
        event_type = 'ROOT'
        event_data = 'example event data'
        module = 'example module'
        source_event = SpiderFootEvent(event_type, event_data, module, "ROOT")

        event_type = 'not ROOT'
        evt = SpiderFootEvent(event_type, event_data, module, source_event)
        evt_hash = evt.hash

        self.assertIsInstance(evt_hash, str)
