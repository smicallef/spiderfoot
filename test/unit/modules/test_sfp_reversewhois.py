import pytest
import unittest

from modules.sfp_reversewhois import sfp_reversewhois
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleReversewhois(unittest.TestCase):

    def test_opts(self):
        module = sfp_reversewhois()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_reversewhois()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_reversewhois()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_reversewhois()
        self.assertIsInstance(module.producedEvents(), list)
