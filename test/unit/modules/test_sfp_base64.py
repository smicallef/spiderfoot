import pytest
import unittest

from modules.sfp_base64 import sfp_base64
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleBase64(unittest.TestCase):

    def test_opts(self):
        module = sfp_base64()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_base64()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_base64()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_base64()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_event_data_url_containing_base64_string_should_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_base64()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'BASE64_DATA'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = "U3BpZGVyRm9vdA== (SpiderFoot)"
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_base64)

        event_type = 'ROOT'
        event_data = 'https://spiderfoot.net/path?param=example%20data%20U3BpZGVyRm9vdA%3d%3d%20example%20data'
        event_module = ''
        source_event = ''

        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    def test_handleEvent_event_data_not_containing_base64_string_should_not_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_base64()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_base64)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''

        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)
