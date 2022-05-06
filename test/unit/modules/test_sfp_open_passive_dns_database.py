import pytest
import unittest

from modules.sfp_open_passive_dns_database import sfp_open_passive_dns_database
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleOpen_passive_dns_database(unittest.TestCase):

    def test_opts(self):
        module = sfp_open_passive_dns_database()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_open_passive_dns_database()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_open_passive_dns_database()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_open_passive_dns_database()
        self.assertIsInstance(module.producedEvents(), list)
