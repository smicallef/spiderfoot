import pytest
import unittest

from modules.sfp_opennic import sfp_opennic
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleOpenNic(unittest.TestCase):

    def test_opts(self):
        module = sfp_opennic()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_opennic()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_opennic()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_opennic()
        self.assertIsInstance(module.producedEvents(), list)
