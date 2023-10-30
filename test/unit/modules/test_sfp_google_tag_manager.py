import pytest
import unittest

from modules.sfp_google_tag_manager import sfp_google_tag_manager
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModulesGoogleTagManager(unittest.TestCase):

    def test_opts(self):
        module = sfp_google_tag_manager()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_google_tag_manager()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_google_tag_manager()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_google_tag_manager()
        self.assertIsInstance(module.producedEvents(), list)
