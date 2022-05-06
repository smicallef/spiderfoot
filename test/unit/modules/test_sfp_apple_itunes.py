import pytest
import unittest

from modules.sfp_apple_itunes import sfp_apple_itunes
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleAppleItunes(unittest.TestCase):

    def test_opts(self):
        module = sfp_apple_itunes()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_apple_itunes()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_apple_itunes()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_apple_itunes()
        self.assertIsInstance(module.producedEvents(), list)
