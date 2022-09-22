import pytest
import unittest

from modules.sfp_threatcrowd import sfp_threatcrowd
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleThreatcrowd(unittest.TestCase):

    def test_opts(self):
        module = sfp_threatcrowd()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_threatcrowd()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_threatcrowd()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_threatcrowd()
        self.assertIsInstance(module.producedEvents(), list)
