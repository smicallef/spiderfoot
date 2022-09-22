import pytest
import unittest

from modules.sfp_comodo import sfp_comodo
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleComodo(unittest.TestCase):

    def test_opts(self):
        module = sfp_comodo()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_comodo()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_comodo()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_comodo()
        self.assertIsInstance(module.producedEvents(), list)
