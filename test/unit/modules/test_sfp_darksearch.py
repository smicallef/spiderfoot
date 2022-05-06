import pytest
import unittest

from modules.sfp_darksearch import sfp_darksearch
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleDarksearch(unittest.TestCase):

    def test_opts(self):
        module = sfp_darksearch()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_darksearch()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_darksearch()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_darksearch()
        self.assertIsInstance(module.producedEvents(), list)
