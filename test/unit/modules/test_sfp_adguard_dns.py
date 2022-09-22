import pytest
import unittest

from modules.sfp_adguard_dns import sfp_adguard_dns
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleAdGuardDns(unittest.TestCase):

    def test_opts(self):
        module = sfp_adguard_dns()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_adguard_dns()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_adguard_dns()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_adguard_dns()
        self.assertIsInstance(module.producedEvents(), list)
