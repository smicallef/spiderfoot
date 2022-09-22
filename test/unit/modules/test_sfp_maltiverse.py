import pytest
import unittest

from modules.sfp_maltiverse import sfp_maltiverse
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleMaltiverse(unittest.TestCase):

    def test_opts(self):
        module = sfp_maltiverse()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_maltiverse()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_maltiverse()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_maltiverse()
        self.assertIsInstance(module.producedEvents(), list)
