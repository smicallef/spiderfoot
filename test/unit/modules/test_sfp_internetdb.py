import pytest
import unittest

from modules.sfp_internetdb import sfp_internetdb
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleShodan(unittest.TestCase):

    def test_opts(self):
        module = sfp_internetdb()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_internetdb()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_internetdb()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_internetdb()
        self.assertIsInstance(module.producedEvents(), list)
