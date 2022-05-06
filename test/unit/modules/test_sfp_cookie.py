import pytest
import unittest

from modules.sfp_cookie import sfp_cookie
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleCookie(unittest.TestCase):

    def test_opts(self):
        module = sfp_cookie()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_cookie()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_cookie()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_cookie()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_event_data_containing_cookie_should_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_cookie()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'TARGET_WEB_COOKIE'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = 'example cookie'
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_cookie)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'WEBSERVER_HTTPHEADERS'
        event_data = '{"cookie": "example cookie"}'
        event_module = 'sfp_spider'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)
        evt.actualSource = "https://spiderfoot.net/example"

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    def test_handleEvent_event_data_not_containing_cookie_should_not_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_cookie()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_cookie)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'WEBSERVER_HTTPHEADERS'
        event_data = '{"not cookie": "example cookie"}'
        event_module = 'sfp_spider'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)
        evt.actualSource = "https://spiderfoot.net/example"

        result = module.handleEvent(evt)

        self.assertIsNone(result)
