# test_sfp_dnsresolve.py
import pytest
import unittest

from modules.sfp_dnsresolve import sfp_dnsresolve
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleDnsResolve(unittest.TestCase):
    """
    Test modules.sfp_dnsresolve
    """

    def test_opts(self):
        module = sfp_dnsresolve()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        """
        Test setup(self, sfc, userOpts=dict())
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_dnsresolve()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_dnsresolve()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_dnsresolve()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent(self):
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

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        event_type = 'RAW_RIR_DATA'
        event_data = 'example data spiderfoot.net example data'
        event_module = 'example module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        result = module.handleEvent(evt)

        self.assertIsNone(result)
        self.assertEqual('TODO', 'TODO')

    def test_enrichTarget_should_return_SpiderFootTarget(self):
        """
        Test enrichTarget(self, target)
        """
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

    def test_processDomain_should_return_None(self):
        """
        Test processDomain(self, domainName, parentEvent, affil=False, host=None)

        Todo:
            review: why should this return None?
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_dnsresolve()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = 'example module'
        source_event = ''
        parent_event = SpiderFootEvent(event_type, event_data, event_module, source_event)

        result = module.processDomain('www.example.local', parent_event, None, None)

        self.assertIsNone(result)
        self.assertEqual('TODO', 'TODO')

    def test_processHost_ip_address_should_return_ip_address_event(self):
        """
        Test processHost(self, host, parentEvent, affiliate=None)
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_dnsresolve()
        module.setup(sf, dict())

        target_value = '127.0.0.1'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = 'example module'
        source_event = ''
        parent_event = SpiderFootEvent(event_type, event_data, event_module, source_event)

        host = '127.0.0.1'
        result = module.processHost(host, parent_event, False)

        self.assertIsInstance(result, SpiderFootEvent)
        self.assertEqual(result.data, host)
        self.assertEqual(result.eventType, 'IP_ADDRESS')

    def test_processHost_affiliate_ip_address_should_return_affiliate_ip_address_event(self):
        """
        Test processHost(self, host, parentEvent, affiliate=None)
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_dnsresolve()
        module.setup(sf, dict())

        target_value = '127.0.0.1'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = 'example module'
        source_event = ''
        parent_event = SpiderFootEvent(event_type, event_data, event_module, source_event)

        host = '127.0.0.1'
        result = module.processHost(host, parent_event, True)

        self.assertIsInstance(result, SpiderFootEvent)
        self.assertEqual(result.data, host)
        self.assertEqual(result.eventType, 'AFFILIATE_IPADDR')

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

        event_type = 'IP_ADDRESS'
        event_data = '1.1.1.1'
        event_module = 'example module'
        source_event = evt
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        with self.assertRaises(Exception) as cm:
            module.handleEvent(evt)

        self.assertEqual("OK", str(cm.exception))
