import pytest
import unittest

from modules.sfp_emailformat import sfp_emailformat
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleEmailformat(unittest.TestCase):

    def test_opts(self):
        module = sfp_emailformat()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_emailformat()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_emailformat()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_emailformat()
        self.assertIsInstance(module.producedEvents(), list)
