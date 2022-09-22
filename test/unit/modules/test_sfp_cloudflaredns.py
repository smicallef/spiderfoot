import pytest
import unittest

from modules.sfp_cloudflaredns import sfp_cloudflaredns
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleCloudflaredns(unittest.TestCase):

    def test_opts(self):
        module = sfp_cloudflaredns()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_cloudflaredns()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_cloudflaredns()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_cloudflaredns()
        self.assertIsInstance(module.producedEvents(), list)
