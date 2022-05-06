import pytest
import unittest

from modules.sfp_abusech import sfp_abusech
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleAbusech(unittest.TestCase):

    def test_opts(self):
        module = sfp_abusech()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_abusech()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_abusech()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_abusech()
        self.assertIsInstance(module.producedEvents(), list)
