# test_sfp_opendns.py
import pytest
import unittest

from modules.sfp_opendns import sfp_opendns
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleopendns(unittest.TestCase):
    """
    Test modules.sfp_opendns
    """

    def test_opts(self):
        module = sfp_opendns()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        """
        Test setup(self, sfc, userOpts=dict())
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_opendns()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_opendns()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_opendns()
        self.assertIsInstance(module.producedEvents(), list)

    def test_queryAddr_should_resolve_unblocked_host(self):
        """
        Test queryAddr(self, qaddr)
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_opendns()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        resolved = module.queryAddr('opendns.com')
        self.assertTrue(resolved)

    def test_handleEvent(self):
        """
        Test handleEvent(self, event)
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_opendns()
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
