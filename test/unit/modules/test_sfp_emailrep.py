import pytest
import unittest

from modules.sfp_emailrep import sfp_emailrep
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleEmailrep(unittest.TestCase):

    def test_opts(self):
        module = sfp_emailrep()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_emailrep()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_emailrep()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_emailrep()
        self.assertIsInstance(module.producedEvents(), list)
