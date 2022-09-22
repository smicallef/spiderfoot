import pytest
import unittest

from modules.sfp_cybercrimetracker import sfp_cybercrimetracker
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleCybercrimetracker(unittest.TestCase):

    def test_opts(self):
        module = sfp_cybercrimetracker()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_cybercrimetracker()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_cybercrimetracker()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_cybercrimetracker()
        self.assertIsInstance(module.producedEvents(), list)
