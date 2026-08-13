import unittest

from modules.sfp_lunarcyber import sfp_lunarcyber
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent


class TestModuleLunarcyber(unittest.TestCase):

    def test_opts(self):
        module = sfp_lunarcyber()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_lunarcyber()
        module.opts = dict(module.opts)
        module.setup(sf, {'_internettlds': 'com,net,org', '_fetchtimeout': 30, '_useragent': 'SpiderFoot/Test'})

    def test_watchedEvents_should_return_list(self):
        module = sfp_lunarcyber()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_lunarcyber()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_with_exposure(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_lunarcyber()
        module.opts = dict(module.opts)
        module.setup(sf, {'_internettlds': 'com,net,org', '_fetchtimeout': 30, '_useragent': 'SpiderFoot/Test'})

        module.sf.validHost = lambda *args, **kwargs: True
        module.sf.fetchUrl = lambda *args, **kwargs: {
            'code': '200',
            'content': '{"domain": "example.com", "exposure_count": 3, "malware_families": ["Redline", "Vidar"]}'
        }

        root = SpiderFootEvent('ROOT', 'example.com', 'sfp_test', None)
        evt = SpiderFootEvent('INTERNET_NAME', 'example.com', 'sfp_test', root)
        notified = []
        module.notifyListeners = lambda e: notified.append(e)

        module.handleEvent(evt)

        self.assertEqual(len(notified), 1)
        self.assertEqual(notified[0].eventType, 'MALICIOUS_INTERNET_NAME')
        self.assertIn('3 exposure', notified[0].data)

    def test_handleEvent_no_exposure(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_lunarcyber()
        module.opts = dict(module.opts)
        module.setup(sf, {'_internettlds': 'com,net,org', '_fetchtimeout': 30, '_useragent': 'SpiderFoot/Test'})

        module.sf.validHost = lambda *args, **kwargs: True
        module.sf.fetchUrl = lambda *args, **kwargs: {
            'code': '200',
            'content': '{"domain": "example.com", "exposure_count": 0}'
        }

        root = SpiderFootEvent('ROOT', 'example.com', 'sfp_test', None)
        evt = SpiderFootEvent('INTERNET_NAME', 'example.com', 'sfp_test', root)
        notified = []
        module.notifyListeners = lambda e: notified.append(e)

        module.handleEvent(evt)

        self.assertEqual(len(notified), 0)
