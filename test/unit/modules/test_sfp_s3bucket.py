import pytest
import unittest

from modules.sfp_s3bucket import sfp_s3bucket
from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestModuleS3bucket(unittest.TestCase):

    def test_opts(self):
        module = sfp_s3bucket()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_s3bucket()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_s3bucket()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_s3bucket()
        self.assertIsInstance(module.producedEvents(), list)
