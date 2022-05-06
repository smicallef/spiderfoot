import pytest
import unittest

from modules.sfp_phishtank import sfp_phishtank
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModulePhishtank(unittest.TestCase):

    def test_opts(self):
        module = sfp_phishtank()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_phishtank()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_phishtank()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_phishtank()
        self.assertIsInstance(module.producedEvents(), list)
