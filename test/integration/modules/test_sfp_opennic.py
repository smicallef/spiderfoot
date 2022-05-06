import pytest
import unittest

from modules.sfp_opennic import sfp_opennic
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleIntegrationOpenNic(unittest.TestCase):

    def test_handleEvent_event_data_internet_name_with_opennic_tld_should_return_ip_address_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_opennic()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'IP_ADDRESS'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_opennic)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'INTERNET_NAME'
        event_data = 'opennic.glue'
        event_module = 'example module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))
