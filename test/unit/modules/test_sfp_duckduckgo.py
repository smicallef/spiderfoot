import pytest
import unittest

from modules.sfp_duckduckgo import sfp_duckduckgo
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleDuckduckgo(unittest.TestCase):

    def test_opts(self):
        module = sfp_duckduckgo()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_duckduckgo()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_duckduckgo()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_duckduckgo()
        self.assertIsInstance(module.producedEvents(), list)
