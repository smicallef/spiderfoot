import pytest
import unittest

from modules.sfp_portscan_tcp import sfp_portscan_tcp
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModulePortscanTcp(unittest.TestCase):

    def test_opts(self):
        module = sfp_portscan_tcp()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_portscan_tcp()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_portscan_tcp()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_portscan_tcp()
        self.assertIsInstance(module.producedEvents(), list)
