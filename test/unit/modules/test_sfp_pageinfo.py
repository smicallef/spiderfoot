import pytest
import unittest

from modules.sfp_pageinfo import sfp_pageinfo
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModulePageInfo(unittest.TestCase):

    def test_opts(self):
        module = sfp_pageinfo()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_pageinfo()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_pageinfo()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_pageinfo()
        self.assertIsInstance(module.producedEvents(), list)
