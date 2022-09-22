import pytest
import unittest

from modules.sfp_spamcop import sfp_spamcop
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleSpamcop(unittest.TestCase):

    def test_opts(self):
        module = sfp_spamcop()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_spamcop()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_spamcop()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_spamcop()
        self.assertIsInstance(module.producedEvents(), list)
