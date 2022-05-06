import pytest
import unittest

from modules.sfp_filemeta import sfp_filemeta
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleFilemeta(unittest.TestCase):

    def test_opts(self):
        module = sfp_filemeta()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_filemeta()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_filemeta()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_filemeta()
        self.assertIsInstance(module.producedEvents(), list)
