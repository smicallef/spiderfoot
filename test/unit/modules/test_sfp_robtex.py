import pytest
import unittest

from modules.sfp_robtex import sfp_robtex
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleRobtex(unittest.TestCase):

    def test_opts(self):
        module = sfp_robtex()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_robtex()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_robtex()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_robtex()
        self.assertIsInstance(module.producedEvents(), list)
