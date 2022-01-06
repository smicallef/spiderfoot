# test_sfp_spamhaus.py
import pytest
import unittest

from modules.sfp_spamhaus import sfp_spamhaus
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModulespamhaus(unittest.TestCase):
    """
    Test modules.sfp_spamhaus
    """

    def test_opts(self):
        module = sfp_spamhaus()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        """
        Test setup(self, sfc, userOpts=dict())
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_spamhaus()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_spamhaus()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_spamhaus()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_event_data_safe_ip_address_not_blocked_should_not_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_spamhaus()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_spamhaus)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'IP_ADDRESS'
        event_data = '1.0.0.1'
        event_module = 'example module'
        source_event = evt

        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)
