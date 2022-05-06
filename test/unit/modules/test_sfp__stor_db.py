import pytest
import unittest

from modules.sfp__stor_db import sfp__stor_db
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleStor_db(unittest.TestCase):

    @unittest.skip("This module contains an extra private option")
    def test_opts(self):
        module = sfp__stor_db()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp__stor_db()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp__stor_db()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp__stor_db()
        self.assertIsInstance(module.producedEvents(), list)
