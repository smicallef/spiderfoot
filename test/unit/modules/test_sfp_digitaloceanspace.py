import pytest
import unittest

from modules.sfp_digitaloceanspace import sfp_digitaloceanspace
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleDigitaloceanspace(unittest.TestCase):

    def test_opts(self):
        module = sfp_digitaloceanspace()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_digitaloceanspace()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_digitaloceanspace()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_digitaloceanspace()
        self.assertIsInstance(module.producedEvents(), list)
