# test_sfp_quad9.py
import pytest
import unittest

from modules.sfp_quad9 import sfp_quad9
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModulequad9(unittest.TestCase):
    """
    Test modules.sfp_quad9
    """

    def test_opts(self):
        module = sfp_quad9()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        """
        Test setup(self, sfc, userOpts=dict())
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_quad9()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_quad9()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_quad9()
        self.assertIsInstance(module.producedEvents(), list)

    def test_query_should_resolve_unblocked_host(self):
        """
        Test query(self, qaddr)
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_quad9()
        module.setup(sf, dict())

        target_value = 'spiderfoot.net'
        target_type = 'INTERNET_NAME'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        resolved = module.query('quad9.net')
        self.assertTrue(resolved)

    def test_handleEvent(self):
        """
        Test handleEvent(self, event)
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_quad9()
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
