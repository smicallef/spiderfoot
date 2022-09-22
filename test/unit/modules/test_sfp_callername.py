import pytest
import unittest

from modules.sfp_callername import sfp_callername
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleCallername(unittest.TestCase):

    def test_opts(self):
        module = sfp_callername()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_callername()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_callername()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_callername()
        self.assertIsInstance(module.producedEvents(), list)
