import pytest
import unittest

from modules.sfp_sublist3r import sfp_sublist3r
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleSublist3r(unittest.TestCase):

    def test_opts(self):
        module = sfp_sublist3r()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_sublist3r()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_sublist3r()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_sublist3r()
        self.assertIsInstance(module.producedEvents(), list)
