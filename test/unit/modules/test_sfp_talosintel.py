import pytest
import unittest

from modules.sfp_talosintel import sfp_talosintel
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleTalosintel(unittest.TestCase):

    def test_opts(self):
        module = sfp_talosintel()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_talosintel()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_talosintel()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_talosintel()
        self.assertIsInstance(module.producedEvents(), list)
