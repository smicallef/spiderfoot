import pytest
import unittest

from modules.sfp_opendns import sfp_opendns
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleOpendns(unittest.TestCase):

    def test_opts(self):
        module = sfp_opendns()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_opendns()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_opendns()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_opendns()
        self.assertIsInstance(module.producedEvents(), list)
