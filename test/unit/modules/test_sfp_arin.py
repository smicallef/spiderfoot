import pytest
import unittest

from modules.sfp_arin import sfp_arin
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleArin(unittest.TestCase):

    def test_opts(self):
        module = sfp_arin()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_arin()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_arin()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_arin()
        self.assertIsInstance(module.producedEvents(), list)
