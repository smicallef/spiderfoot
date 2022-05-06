import pytest
import unittest

from modules.sfp_openphish import sfp_openphish
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleOpenphish(unittest.TestCase):

    def test_opts(self):
        module = sfp_openphish()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_openphish()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_openphish()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_openphish()
        self.assertIsInstance(module.producedEvents(), list)
