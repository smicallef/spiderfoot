import pytest
import unittest

from modules.sfp_urlscan import sfp_urlscan
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleUrlscan(unittest.TestCase):

    def test_opts(self):
        module = sfp_urlscan()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_urlscan()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_urlscan()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_urlscan()
        self.assertIsInstance(module.producedEvents(), list)
