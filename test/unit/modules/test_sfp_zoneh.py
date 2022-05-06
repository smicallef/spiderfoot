import pytest
import unittest

from modules.sfp_zoneh import sfp_zoneh
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleZoneh(unittest.TestCase):

    def test_opts(self):
        module = sfp_zoneh()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_zoneh()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_zoneh()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_zoneh()
        self.assertIsInstance(module.producedEvents(), list)
