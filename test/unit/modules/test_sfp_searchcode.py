import pytest
import unittest

from modules.sfp_searchcode import sfp_searchcode
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleCodesearch(unittest.TestCase):

    def test_opts(self):
        module = sfp_searchcode()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_searchcode()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_searchcode()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_searchcode()
        self.assertIsInstance(module.producedEvents(), list)
