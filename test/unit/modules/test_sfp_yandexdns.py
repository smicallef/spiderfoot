import pytest
import unittest

from modules.sfp_yandexdns import sfp_yandexdns
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleYandexdns(unittest.TestCase):

    def test_opts(self):
        module = sfp_yandexdns()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_yandexdns()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_yandexdns()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_yandexdns()
        self.assertIsInstance(module.producedEvents(), list)
