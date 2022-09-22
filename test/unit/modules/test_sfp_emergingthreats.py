import pytest
import unittest

from modules.sfp_emergingthreats import sfp_emergingthreats
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleEmergingthreats(unittest.TestCase):

    def test_opts(self):
        module = sfp_emergingthreats()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_emergingthreats()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_emergingthreats()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_emergingthreats()
        self.assertIsInstance(module.producedEvents(), list)
