import pytest
import unittest

from modules.sfp_strangeheaders import sfp_strangeheaders
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleStrangeHeaders(unittest.TestCase):

    def test_opts(self):
        module = sfp_strangeheaders()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_strangeheaders()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_strangeheaders()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_strangeheaders()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_event_data_containing_unusual_header_should_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_strangeheaders()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'WEBSERVER_STRANGEHEADER'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = 'unusual header: example header value'
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_strangeheaders)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'WEBSERVER_HTTPHEADERS'
        event_data = '{"unusual header": "example header value"}'
        event_module = 'sfp_spider'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)
        evt.actualSource = "https://spiderfoot.net/example"

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    def test_handleEvent_event_data_not_containing_unusual_header_should_not_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_strangeheaders()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_strangeheaders)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'WEBSERVER_HTTPHEADERS'
        event_data = '{"server": "example server"}'
        event_module = 'sfp_spider'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)
        evt.actualSource = "https://spiderfoot.net/example"

        result = module.handleEvent(evt)

        self.assertIsNone(result)
