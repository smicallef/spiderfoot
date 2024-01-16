import unittest

import pytest

from modules.sfp_whoisfreaks import sfp_whoisfreaks
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleWhoisfreaks(unittest.TestCase):

    def test_opts(self):
        module = sfp_whoisfreaks()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_whoisfreaks()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_whoisfreaks()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_whoisfreaks()
        self.assertIsInstance(module.producedEvents(), list)