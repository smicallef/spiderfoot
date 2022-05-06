import pytest
import unittest

from modules.sfp_uceprotect import sfp_uceprotect
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleUceprotect(unittest.TestCase):

    def test_opts(self):
        module = sfp_uceprotect()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_uceprotect()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_uceprotect()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_uceprotect()
        self.assertIsInstance(module.producedEvents(), list)
