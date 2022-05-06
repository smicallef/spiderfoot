import pytest
import unittest

from modules.sfp_googlemaps import sfp_googlemaps
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleGoogleMaps(unittest.TestCase):

    def test_opts(self):
        module = sfp_googlemaps()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_googlemaps()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_googlemaps()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_googlemaps()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_no_api_key_should_set_errorState(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_googlemaps()
        module.setup(sf, dict())

        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        result = module.handleEvent(evt)

        self.assertIsNone(result)
        self.assertTrue(module.errorState)
