import pytest
import unittest

from modules.sfp_spamhaus import sfp_spamhaus
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleSpamhaus(unittest.TestCase):

    def test_opts(self):
        module = sfp_spamhaus()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_spamhaus()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_spamhaus()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_spamhaus()
        self.assertIsInstance(module.producedEvents(), list)
