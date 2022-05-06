import pytest
import unittest

from modules.sfp_dnscommonsrv import sfp_dnscommonsrv
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleDnsCommonsrv(unittest.TestCase):

    def test_opts(self):
        module = sfp_dnscommonsrv()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_dnscommonsrv()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_dnscommonsrv()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_dnscommonsrv()
        self.assertIsInstance(module.producedEvents(), list)
