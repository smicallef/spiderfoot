import pytest
import unittest

from modules.sfp_openstreetmap import sfp_openstreetmap
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleopenstreetmap(unittest.TestCase):

    def test_opts(self):
        module = sfp_openstreetmap()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_openstreetmap()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_openstreetmap()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_openstreetmap()
        self.assertIsInstance(module.producedEvents(), list)
