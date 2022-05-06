import pytest
import unittest

from modules.sfp_ipqualityscore import sfp_ipqualityscore
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleIntegrationIpqualityscore(unittest.TestCase):

    @unittest.skip("todo")
    def test_handleEvent(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_ipqualityscore()
        module.setup(sf, dict())

        target_value = 'example target value'
        target_type = 'PHONE_NUMBER'
        target = SpiderFootTarget(target_value, target_type)
        module.setTarget(target)

        event_type = 'ROOT'
        event_data = 'example data'
        event_module = ''
        source_event = ''
        evt = SpiderFootEvent(event_type, event_data, event_module, source_event)

        result = module.handleEvent(evt)

        self.assertIsNone(result)
