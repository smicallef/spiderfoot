import pytest
import unittest

from modules.sfp_bgpview import sfp_bgpview
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleBgpview(unittest.TestCase):

    def test_opts(self):
        module = sfp_bgpview()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_bgpview()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_bgpview()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_bgpview()
        self.assertIsInstance(module.producedEvents(), list)
