import pytest
import unittest

from modules.sfp_archiveorg import sfp_archiveorg
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleArchiveorg(unittest.TestCase):

    def test_opts(self):
        module = sfp_archiveorg()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_archiveorg()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_archiveorg()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_archiveorg()
        self.assertIsInstance(module.producedEvents(), list)
