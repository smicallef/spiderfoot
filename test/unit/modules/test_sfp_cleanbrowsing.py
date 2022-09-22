import pytest
import unittest

from modules.sfp_cleanbrowsing import sfp_cleanbrowsing
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleCleanbrowsing(unittest.TestCase):

    def test_opts(self):
        module = sfp_cleanbrowsing()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_cleanbrowsing()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_cleanbrowsing()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_cleanbrowsing()
        self.assertIsInstance(module.producedEvents(), list)
