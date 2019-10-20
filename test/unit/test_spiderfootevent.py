# test_spiderfootevent.py
from sflib import SpiderFootEvent
import unittest

class TestSpiderFootEvent(unittest.TestCase):
    """
    Test SpiderFootEvent
    """
 
    def test_init(self):
        """
        Test __init__(self, eventType, data, module, sourceEvent, confidence=100, visibility=100, risk=0)
        """
        event_type = 'ROOT'
        event_data = ''
        module = ''
        source_event = ''
        confidence = 100
        visibility = 100
        risk = 0

        evt = SpiderFootEvent(event_type, event_data, module, source_event, confidence, visibility)
        self.assertEqual('TBD', 'TBD')

    def test_asdict(self):
        """
        Test asDict(self)
        """
        self.assertEqual('TBD', 'TBD')

    def test_get_hash(self):
        """
        Test getHash(self)
        """
        self.assertEqual('TBD', 'TBD')

    def test_set_confidence(self):
        """
        Test setConfidence(self, confidence)
        """
        self.assertEqual('TBD', 'TBD')

    def test_set_visibility(self):
        """
        Test setVisibility(self, visibility)
        """
        self.assertEqual('TBD', 'TBD')

    def test_set_risk(self):
        """
        Test setRisk(self, risk)
        """
        self.assertEqual('TBD', 'TBD')

    def test_set_source_event_hash(self):
        """
        Test setSourceEventHash(self, srcHash)
        """
        self.assertEqual('TBD', 'TBD')

if __name__ == '__main__':
    unittest.main()

