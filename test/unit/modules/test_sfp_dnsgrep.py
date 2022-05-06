import pytest
import unittest

from modules.sfp_dnsgrep import sfp_dnsgrep
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleDnsGrep(unittest.TestCase):

    def test_opts(self):
        module = sfp_dnsgrep()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_dnsgrep()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_dnsgrep()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_dnsgrep()
        self.assertIsInstance(module.producedEvents(), list)
