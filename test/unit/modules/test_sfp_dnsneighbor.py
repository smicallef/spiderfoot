import pytest
import unittest

from modules.sfp_dnsneighbor import sfp_dnsneighbor
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleDnsNeighbor(unittest.TestCase):

    def test_opts(self):
        module = sfp_dnsneighbor()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_dnsneighbor()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_dnsneighbor()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_dnsneighbor()
        self.assertIsInstance(module.producedEvents(), list)
