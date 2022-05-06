import pytest
import unittest

from modules.sfp_multiproxy import sfp_multiproxy
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleMultiproxy(unittest.TestCase):

    def test_opts(self):
        module = sfp_multiproxy()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_multiproxy()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_multiproxy()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_multiproxy()
        self.assertIsInstance(module.producedEvents(), list)
