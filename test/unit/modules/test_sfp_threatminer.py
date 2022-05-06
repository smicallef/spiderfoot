import pytest
import unittest

from modules.sfp_threatminer import sfp_threatminer
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleThreatminer(unittest.TestCase):

    def test_opts(self):
        module = sfp_threatminer()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_threatminer()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_threatminer()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_threatminer()
        self.assertIsInstance(module.producedEvents(), list)
