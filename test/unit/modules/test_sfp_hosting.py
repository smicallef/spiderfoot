import pytest
import unittest

from modules.sfp_hosting import sfp_hosting
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleHosting(unittest.TestCase):

    def test_opts(self):
        module = sfp_hosting()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_hosting()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_hosting()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_hosting()
        self.assertIsInstance(module.producedEvents(), list)
