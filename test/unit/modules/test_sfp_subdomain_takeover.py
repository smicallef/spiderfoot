import pytest
import unittest

from modules.sfp_subdomain_takeover import sfp_subdomain_takeover
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleSubdomain_takeover(unittest.TestCase):

    def test_opts(self):
        module = sfp_subdomain_takeover()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_subdomain_takeover()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_subdomain_takeover()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_subdomain_takeover()
        self.assertIsInstance(module.producedEvents(), list)
