import pytest
import unittest

from modules.sfp_sorbs import sfp_sorbs
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleSorbs(unittest.TestCase):

    def test_opts(self):
        module = sfp_sorbs()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_sorbs()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_sorbs()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_sorbs()
        self.assertIsInstance(module.producedEvents(), list)
