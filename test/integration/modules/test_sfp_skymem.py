import pytest
import unittest

from modules.sfp_skymem import sfp_skymem
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleIntegrationSkymem(unittest.TestCase):

    @unittest.skip("todo")
    def test_handleEvent(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_skymem()
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
