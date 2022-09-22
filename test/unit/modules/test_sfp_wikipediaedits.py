import pytest
import unittest

from modules.sfp_wikipediaedits import sfp_wikipediaedits
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModulewikipediaedits(unittest.TestCase):

    def test_opts(self):
        module = sfp_wikipediaedits()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_wikipediaedits()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_wikipediaedits()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_wikipediaedits()
        self.assertIsInstance(module.producedEvents(), list)
