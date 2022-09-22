import pytest
import unittest

from modules.sfp_quad9 import sfp_quad9
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleQuad9(unittest.TestCase):

    def test_opts(self):
        module = sfp_quad9()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_quad9()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_quad9()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_quad9()
        self.assertIsInstance(module.producedEvents(), list)
