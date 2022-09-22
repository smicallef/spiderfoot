import pytest
import unittest

from modules.sfp_phishstats import sfp_phishstats
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModulePhishstats(unittest.TestCase):

    def test_opts(self):
        module = sfp_phishstats()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_phishstats()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_phishstats()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_phishstats()
        self.assertIsInstance(module.producedEvents(), list)
