import pytest
import unittest

from modules.sfp_stevenblack_hosts import sfp_stevenblack_hosts
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleIntegrationStevenblackHosts(unittest.TestCase):

    def test_handleEvent_event_data_affiliate_internet_name_matching_ad_server_should_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_stevenblack_hosts()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        module.opts['_fetchtimeout'] = 15
        module.optdescs['_fetchtimeout'] = ''
        module.opts['_useragent'] = ''
        module.optdescs['_useragent'] = ''

        def new_notifyListeners(self, event):
            expected = 'MALICIOUS_AFFILIATE_INTERNET_NAME'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = 'Steven Black Hosts Blocklist [ads.google.com]\n<SFURL>https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts</SFURL>'
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_stevenblack_hosts)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'AFFILIATE_INTERNET_NAME'
        event_data = 'ads.google.com'
        event_module = 'example module'
        source_event = evt

        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    def test_handleEvent_event_data_affiliate_internet_name_not_matching_ad_server_should_not_return_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_stevenblack_hosts()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        module.opts['_fetchtimeout'] = 15
        module.optdescs['_fetchtimeout'] = ''
        module.opts['_useragent'] = ''
        module.optdescs['_useragent'] = ''

        def new_notifyListeners(self, event):
            raise Exception(f"Raised event {event.eventType}: {event.data}")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_stevenblack_hosts)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'AFFILIATE_INTERNET_NAME'
        event_data = 'no.ads.safe.local'
        event_module = 'example module'
        source_event = evt

        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)
        result = module.handleEvent(evt)

        self.assertIsNone(result)
