import json
import unittest
import pytest

from modules.sfp_lunarcyber import sfp_lunarcyber
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleLunarCyber(unittest.TestCase):

    def test_opts(self):
        module = sfp_lunarcyber()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_lunarcyber()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_lunarcyber()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_lunarcyber()
        self.assertIsInstance(module.producedEvents(), list)

    def test_parseApiResponse_http_error_should_return_none(self):
        module = sfp_lunarcyber()

        res = {
            'code': '500',
            'status': 'Internal Server Error',
            'content': ''
        }

        result = module.parseApiResponse(res)

        self.assertIsNone(result)

    def test_parseApiResponse_invalid_json_should_return_none(self):
        module = sfp_lunarcyber()

        res = {
            'code': '200',
            'status': '',
            'content': 'not json'
        }

        result = module.parseApiResponse(res)

        self.assertIsNone(result)

    def test_parseApiResponse_valid_json_should_return_data(self):
        module = sfp_lunarcyber()

        data = {
            'status': 'REPORT_READY',
            'report': {
                'summary': {
                    'total_events': 10
                }
            }
        }

        res = {
            'code': '200',
            'status': '',
            'content': json.dumps(data)
        }

        result = module.parseApiResponse(res)

        self.assertEqual(data, result)

    def _run_handle_event(self, module, mocked_response, event_data='example.com'):
        """Run handleEvent with a mocked fetchUrl response.

        Args:
            module: module instance
            mocked_response: mocked fetchUrl response
            event_data (str): event data

        Returns:
            list: emitted (event_type, event_data) tuples
        """

        module.opts = dict(module.opts)
        module.opts['_fetchtimeout'] = 30
        module.opts['_useragent'] = 'Mozilla/5.0'
        module.sf.fetchUrl = lambda url, timeout, useragent: mocked_response

        emitted = []

        def new_notifyListeners(self, event):
            emitted.append((event.eventType, event.data))

        module.notifyListeners = new_notifyListeners.__get__(module, sfp_lunarcyber)

        target = SpiderFootTarget(event_data, 'INTERNET_NAME')
        module.setTarget(target)

        source_evt = SpiderFootEvent('ROOT', event_data, 'sfp_test', '')
        evt = SpiderFootEvent('INTERNET_NAME', event_data, 'sfp_test', source_evt)
        module.handleEvent(evt)

        return emitted # noqa R504

    def test_handleEvent_report_ready_should_emit_raw_and_malicious_events(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_lunarcyber()
        module.setup(sf, dict())

        report = {
            'domain': 'example.com',
            'summary': {
                'total_events': 100,
                'infostealer_events': 40,
                'data_breach_events': 60,
                'employee_events': 90,
                'client_events': 10,
                'first_seen': '2025-08-13',
                'last_seen': '2026-07-31'
            },
            'malware_family_breakdown': [
                {'family': 'Redline', 'events': 30},
                {'family': 'Lumma', 'events': 10}
            ]
        }

        data = {
            'status': 'REPORT_READY',
            'report': report
        }

        mocked_response = {
            'code': '200',
            'status': '',
            'content': json.dumps(data)
        }

        emitted = self._run_handle_event(module, mocked_response)

        event_types = [e[0] for e in emitted]

        self.assertIn('RAW_RIR_DATA', event_types)
        self.assertIn('MALICIOUS_INTERNET_NAME', event_types)

        raw_event = [e for e in emitted if e[0] == 'RAW_RIR_DATA'][0]
        self.assertEqual(str(report), raw_event[1])

        malicious_event = [e for e in emitted if e[0] == 'MALICIOUS_INTERNET_NAME'][0]
        self.assertIn('100 exposure(s)', malicious_event[1])
        self.assertIn('40 infostealer', malicious_event[1])
        self.assertIn('60 data breach', malicious_event[1])
        self.assertIn('Redline', malicious_event[1])
        self.assertIn('Lumma', malicious_event[1])

    def test_handleEvent_report_generating_should_not_emit_events(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_lunarcyber()
        module.setup(sf, dict())

        data = {
            'status': 'GENERATING_REPORT',
            'report': None
        }

        mocked_response = {
            'code': '200',
            'status': '',
            'content': json.dumps(data)
        }

        emitted = self._run_handle_event(module, mocked_response)

        self.assertEqual([], emitted)

    def test_handleEvent_report_not_authorized_should_not_emit_events(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_lunarcyber()
        module.setup(sf, dict())

        data = {
            'status': 'NOT_AUTHORIZED',
            'report': None
        }

        mocked_response = {
            'code': '200',
            'status': '',
            'content': json.dumps(data)
        }

        emitted = self._run_handle_event(module, mocked_response)

        self.assertEqual([], emitted)

    def test_handleEvent_http_error_should_not_emit_events(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_lunarcyber()
        module.setup(sf, dict())

        mocked_response = {
            'code': '500',
            'status': 'Internal Server Error',
            'content': ''
        }

        emitted = self._run_handle_event(module, mocked_response)

        self.assertEqual([], emitted)

    def test_handleEvent_invalid_json_should_not_emit_events(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_lunarcyber()
        module.setup(sf, dict())

        mocked_response = {
            'code': '200',
            'status': '',
            'content': 'not json'
        }

        emitted = self._run_handle_event(module, mocked_response)

        self.assertEqual([], emitted)

    def test_handleEvent_duplicate_event_should_not_query_twice(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_lunarcyber()
        module.setup(sf, dict())

        query_count = {'n': 0}

        def mock_fetchUrl(url, timeout, useragent):
            query_count['n'] += 1
            return {
                'code': '200',
                'status': '',
                'content': json.dumps({
                    'status': 'GENERATING_REPORT',
                    'report': None
                })
            }

        module.sf.fetchUrl = mock_fetchUrl
        module.opts = dict(module.opts)
        module.opts['_fetchtimeout'] = 30
        module.opts['_useragent'] = 'Mozilla/5.0'

        target = SpiderFootTarget('example.com', 'INTERNET_NAME')
        module.setTarget(target)

        source_evt = SpiderFootEvent('ROOT', 'example.com', 'sfp_test', '')
        evt = SpiderFootEvent('INTERNET_NAME', 'example.com', 'sfp_test', source_evt)
        module.handleEvent(evt)
        module.handleEvent(evt)

        self.assertEqual(1, query_count['n'])

# End of TestModuleLunarCyber class
