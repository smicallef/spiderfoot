import pytest
import unittest

from modules.sfp_isc import sfp_isc
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleisc(unittest.TestCase):

    def test_opts(self):
        module = sfp_isc()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_isc()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_isc()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_isc()
        self.assertIsInstance(module.producedEvents(), list)
