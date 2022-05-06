import pytest
import unittest

from modules.sfp_binstring import sfp_binstring
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleBinstring(unittest.TestCase):

    def test_opts(self):
        module = sfp_binstring()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_binstring()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_binstring()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_binstring()
        self.assertIsInstance(module.producedEvents(), list)
