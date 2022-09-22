import pytest
import unittest

from modules.sfp_trumail import sfp_trumail
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleTrumail(unittest.TestCase):

    def test_opts(self):
        module = sfp_trumail()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_trumail()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_trumail()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_trumail()
        self.assertIsInstance(module.producedEvents(), list)
