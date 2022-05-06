import pytest
import unittest

from modules.sfp_dnsresolve import sfp_dnsresolve
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleIntegrationDnsResolve(unittest.TestCase):

    def test_enrichTarget_should_return_SpiderFootTarget(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_dnsresolve()
        module.setup(sf, dict())

        target_value = '127.0.0.1'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)

        result = module.enrichTarget(target)
        self.assertIsInstance(result, SpiderFootTarget)
        self.assertEqual(result.targetType, target_type)
        self.assertEqual(result.targetValue, target_value)

    def test_resolveTargets_should_return_list(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_dnsresolve()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                resolve_targets = module.resolveTargets(invalid_type, False)
                self.assertIsInstance(resolve_targets, list)

        target = SpiderFootTarget("spiderfoot.net", "INTERNET_NAME")
        resolve_targets = module.resolveTargets(target, False)
        self.assertIsInstance(resolve_targets, list)
        self.assertIn('spiderfoot.net', resolve_targets)

        target = SpiderFootTarget("127.0.0.1", "IP_ADDRESS")
        resolve_targets = module.resolveTargets(target, False)
        self.assertIsInstance(resolve_targets, list)
        self.assertIn('127.0.0.1', resolve_targets)

        target = SpiderFootTarget("::1", "IPV6_ADDRESS")
        resolve_targets = module.resolveTargets(target, False)
        self.assertIsInstance(resolve_targets, list)
        self.assertIn('::1', resolve_targets)

        target = SpiderFootTarget("127.0.0.1/32", "NETBLOCK_OWNER")
        resolve_targets = module.resolveTargets(target, False)
        self.assertIsInstance(resolve_targets, list)
        self.assertIn('127.0.0.1', resolve_targets)

    # note: test fails on MacOSX on CI
    def test_handleEvent_event_data_ip_address_should_return_internet_name_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_dnsresolve()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'INTERNET_NAME'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = "one.one.one.one"
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_dnsresolve)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'IP_ADDRESS'
        event_data = '1.1.1.1'
        event_module = 'example module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    # note: test fails on MacOSX on CI
    def test_handleEvent_event_data_ipv6_address_should_return_internet_name_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_dnsresolve()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'INTERNET_NAME'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = "one.one.one.one"
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_dnsresolve)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'IPV6_ADDRESS'
        event_data = '2606:4700:4700::1111'
        event_module = 'example module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    # note: test fails on MacOSX on CI
    def test_handleEvent_event_data_affiliate_ip_address_should_return_affiliate_internet_name_event(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_dnsresolve()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'AFFILIATE_INTERNET_NAME'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = "one.one.one.one"
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_dnsresolve)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'AFFILIATE_IPADDR'
        event_data = '1.1.1.1'
        event_module = 'example module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))

    def test_handleEvent_event_data_raw_rir_data_containing_subdomain_should_return_internet_name_event(self):
        """
        Test handleEvent(self, event)
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_dnsresolve()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        def new_notifyListeners(self, event):
            expected = 'INTERNET_NAME'
            if str(event.eventType) != expected:
                raise Exception(f"{event.eventType} != {expected}")

            expected = "www.spiderfoot.net"
            if str(event.data) != expected:
                raise Exception(f"{event.data} != {expected}")

            raise Exception("OK")

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_dnsresolve)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'RAW_RIR_DATA'
        event_data = 'example data www.spiderfoot.net example data'
        event_module = 'example module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))
