import pytest
import unittest

from modules.sfp_mnemonic import sfp_mnemonic
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleMnemonic(unittest.TestCase):

    def test_opts(self):
        module = sfp_mnemonic()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_mnemonic()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_mnemonic()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_mnemonic()
        self.assertIsInstance(module.producedEvents(), list)
