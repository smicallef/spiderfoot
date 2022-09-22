import pytest
import unittest

from modules.sfp_ipapico import sfp_ipapico
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleipApico(unittest.TestCase):

    def test_opts(self):
        module = sfp_ipapico()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_ipapico()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ipapico()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ipapico()
        self.assertIsInstance(module.producedEvents(), list)
