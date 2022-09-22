import pytest
import unittest

from modules.sfp_webserver import sfp_webserver
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleWebserver(unittest.TestCase):

    def test_opts(self):
        module = sfp_webserver()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_webserver()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_webserver()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_webserver()
        self.assertIsInstance(module.producedEvents(), list)
