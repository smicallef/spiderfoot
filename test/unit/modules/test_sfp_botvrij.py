import pytest
import unittest

from modules.sfp_botvrij import sfp_botvrij
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModulebotvrij(unittest.TestCase):

    def test_opts(self):
        module = sfp_botvrij()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_botvrij()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_botvrij()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_botvrij()
        self.assertIsInstance(module.producedEvents(), list)
