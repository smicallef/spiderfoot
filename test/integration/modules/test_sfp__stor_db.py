import pytest
import unittest

from modules.sfp__stor_db import sfp__stor_db
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleIntegration_stor_db(unittest.TestCase):

    @unittest.skip("todo")
    def test_handleEvent(self):
        sf = SpiderFoot(self.default_options)

        module = sfp__stor_db()
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
