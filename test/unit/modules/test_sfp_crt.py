import pytest
import unittest

from modules.sfp_crt import sfp_crt
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleCrt(unittest.TestCase):

    def test_opts(self):
        module = sfp_crt()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_crt()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_crt()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_crt()
        self.assertIsInstance(module.producedEvents(), list)
