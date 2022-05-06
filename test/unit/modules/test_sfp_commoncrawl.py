import pytest
import unittest

from modules.sfp_commoncrawl import sfp_commoncrawl
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleCommoncrawl(unittest.TestCase):

    def test_opts(self):
        module = sfp_commoncrawl()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_commoncrawl()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_commoncrawl()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_commoncrawl()
        self.assertIsInstance(module.producedEvents(), list)
