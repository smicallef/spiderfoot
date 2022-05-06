import pytest
import unittest

from modules.sfp_koodous import sfp_koodous
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleKoodous(unittest.TestCase):

    def test_opts(self):
        module = sfp_koodous()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_koodous()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_koodous()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_koodous()
        self.assertIsInstance(module.producedEvents(), list)
