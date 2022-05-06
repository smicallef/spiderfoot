import pytest
import unittest

from modules.sfp_dnsdumpster import sfp_dnsdumpster
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleDnsDumpster(unittest.TestCase):

    def test_opts(self):
        module = sfp_dnsdumpster()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_dnsdumpster()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_dnsdumpster()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_dnsdumpster()
        self.assertIsInstance(module.producedEvents(), list)
