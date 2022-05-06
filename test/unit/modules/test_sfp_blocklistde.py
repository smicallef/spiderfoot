import pytest
import unittest

from modules.sfp_blocklistde import sfp_blocklistde
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleBlocklistde(unittest.TestCase):

    def test_opts(self):
        module = sfp_blocklistde()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_blocklistde()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_blocklistde()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_blocklistde()
        self.assertIsInstance(module.producedEvents(), list)
