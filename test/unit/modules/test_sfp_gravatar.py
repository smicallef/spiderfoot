import pytest
import unittest

from modules.sfp_gravatar import sfp_gravatar
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleGravatar(unittest.TestCase):

    def test_opts(self):
        module = sfp_gravatar()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_gravatar()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_gravatar()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_gravatar()
        self.assertIsInstance(module.producedEvents(), list)
