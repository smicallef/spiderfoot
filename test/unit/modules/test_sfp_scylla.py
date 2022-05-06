import pytest
import unittest

from modules.sfp_scylla import sfp_scylla
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleScylla(unittest.TestCase):

    def test_opts(self):
        module = sfp_scylla()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_scylla()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_scylla()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_scylla()
        self.assertIsInstance(module.producedEvents(), list)
