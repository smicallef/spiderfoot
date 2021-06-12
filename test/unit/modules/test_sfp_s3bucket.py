# test_sfp_s3bucket.py
import pytest
import unittest

from modules.sfp_s3bucket import sfp_s3bucket
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModules3bucket(unittest.TestCase):
    """
    Test modules.sfp_s3bucket
    """

    def test_opts(self):
        module = sfp_s3bucket()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        """
        Test setup(self, sfc, userOpts=dict())
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_s3bucket()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_s3bucket()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_s3bucket()
        self.assertIsInstance(module.producedEvents(), list)

    @unittest.skip("todo")
    def test_handleEvent(self):
        """
        Test handleEvent(self, event)
        """
        sf = SpiderFoot(self.default_options)

        module = sfp_s3bucket()
        module.setup(sf, dict())

        target_value = 'example target value'
        target_type = 'IP_ADDRESS'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        result = module.handleEvent(evt)

        self.assertIsNone(result)
