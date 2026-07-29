import json
import pytest
import unittest

from modules.sfp_xquik import sfp_xquik
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleXquik(unittest.TestCase):

    def module(self, options=None):
        sf = SpiderFoot(self.default_options)
        module = sfp_xquik()
        module.setup(sf, options or dict())

        target = SpiderFootTarget('spiderfoot.net', 'INTERNET_NAME')
        module.setTarget(target)

        return sf, module

    def event(self, eventData="X: <SFURL>https://x.com/xquik</SFURL>"):
        sourceEvent = SpiderFootEvent('ROOT', 'spiderfoot.net', '', '')
        return SpiderFootEvent('SOCIAL_MEDIA', eventData, 'example module', sourceEvent)

    def test_opts(self):
        module = sfp_xquik()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_xquik()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_xquik()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_xquik()
        self.assertIsInstance(module.producedEvents(), list)

    def test_extractHandle_should_parse_x_and_twitter_profile_urls(self):
        module = sfp_xquik()

        self.assertEqual(
            module.extractHandle("X: <SFURL>https://x.com/Xquik</SFURL>"),
            "Xquik"
        )
        self.assertEqual(
            module.extractHandle("Twitter: https://www.twitter.com/xquik/"),
            "xquik"
        )

    def test_extractHandle_should_reject_non_profile_urls(self):
        module = sfp_xquik()

        invalidEvents = [
            None,
            "example data",
            "GitHub: https://github.com/xquik",
            "X: ftp://x.com/xquik",
            "X: https://[xquik",
            "X: https://example.com/xquik",
            "X: https://x.com/home",
            "X: https://x.com/login",
            "X: https://x.com/@xquik",
            "X: https://x.com/sixteencharacters",
            "Twitter: https://twitter.com/xquik/status/1",
        ]

        for eventData in invalidEvents:
            with self.subTest(eventData=eventData):
                self.assertIsNone(module.extractHandle(eventData))

    def test_query_should_use_official_endpoint_and_api_key_header(self):
        sf, module = self.module({"api_key": "test-key"})

        def new_fetchUrl(url, timeout=0, useragent=None, headers=None):
            self.assertEqual("https://xquik.com/api/v1/x/users/xquik", url)
            self.assertEqual(self.default_options['_fetchtimeout'], timeout)
            self.assertEqual(self.default_options['_useragent'], useragent)
            self.assertEqual({
                'Accept': "application/json",
                'x-api-key': "test-key",
            }, headers)
            return {'code': '200', 'content': '{}'}

        sf.fetchUrl = new_fetchUrl

        self.assertEqual({'code': '200', 'content': '{}'}, module.query("xquik"))

    def test_handleEvent_without_api_key_should_set_errorState(self):
        _, module = self.module()

        self.assertIsNone(module.handleEvent(self.event("GitHub: https://github.com/xquik")))
        self.assertFalse(module.errorState)
        self.assertIsNone(module.handleEvent(self.event()))
        self.assertTrue(module.errorState)

    def test_handleEvent_should_emit_profile_events(self):
        sf, module = self.module({"api_key": "test-key"})
        captured = list()

        def new_fetchUrl(url, timeout=0, useragent=None, headers=None):
            return {
                'code': '200',
                'content': json.dumps({
                    'id': "123",
                    'username': "xquik",
                    'name': "Xquik",
                    'location': "Istanbul",
                })
            }

        def new_notifyListeners(self, event):
            captured.append(event)

        sf.fetchUrl = new_fetchUrl
        module.notifyListeners = new_notifyListeners.__get__(module, sfp_xquik)

        self.assertIsNone(module.handleEvent(self.event()))
        self.assertEqual(
            ["RAW_RIR_DATA", "USERNAME", "GEOINFO"],
            [event.eventType for event in captured]
        )
        self.assertEqual("xquik", captured[1].data)
        self.assertEqual("Istanbul", captured[2].data)

    def test_handleEvent_should_skip_duplicate_handles_case_insensitively(self):
        sf, module = self.module({"api_key": "test-key"})
        fetched = list()

        def new_fetchUrl(url, timeout=0, useragent=None, headers=None):
            fetched.append(url)
            return {
                'code': '200',
                'content': json.dumps({
                    'id': "123",
                    'username': "xquik",
                    'name': "Xquik",
                })
            }

        sf.fetchUrl = new_fetchUrl

        module.handleEvent(self.event("X: https://x.com/Xquik"))
        module.handleEvent(self.event("Twitter: https://twitter.com/xquik"))

        self.assertEqual(["https://xquik.com/api/v1/x/users/Xquik"], fetched)

    def test_handleEvent_should_stop_after_authentication_failure(self):
        sf, module = self.module({"api_key": "invalid-key"})

        def new_fetchUrl(url, timeout=0, useragent=None, headers=None):
            return {'code': '401', 'content': '{}'}

        sf.fetchUrl = new_fetchUrl

        self.assertIsNone(module.handleEvent(self.event()))
        self.assertTrue(module.errorState)
        self.assertIsNone(module.handleEvent(self.event("X: https://x.com/another")))

    def test_handleEvent_should_stop_after_fatal_api_errors(self):
        for code in ['402', '403', '429']:
            with self.subTest(code=code):
                sf, module = self.module({"api_key": "test-key"})

                def new_fetchUrl(url, timeout=0, useragent=None, headers=None, code=code):
                    return {'code': code, 'content': '{}'}

                sf.fetchUrl = new_fetchUrl

                self.assertIsNone(module.handleEvent(self.event()))
                self.assertTrue(module.errorState)

    def test_handleEvent_should_ignore_invalid_or_mismatched_profiles(self):
        sf, module = self.module({"api_key": "test-key"})
        captured = list()
        responses = [
            {'code': '200', 'content': "not json"},
            {'code': '200', 'content': json.dumps([])},
            {'code': '200', 'content': json.dumps({})},
            {'code': '200', 'content': json.dumps({'username': "@fourth"})},
            {'code': '200', 'content': json.dumps({'username': "another_user"})},
        ]

        def new_fetchUrl(url, timeout=0, useragent=None, headers=None):
            return responses.pop(0)

        def new_notifyListeners(self, event):
            captured.append(event)

        sf.fetchUrl = new_fetchUrl
        module.notifyListeners = new_notifyListeners.__get__(module, sfp_xquik)

        for handle in ["first", "second", "third", "fourth", "fifth"]:
            module.handleEvent(self.event(f"X: https://x.com/{handle}"))

        self.assertEqual([], captured)

    def test_handleEvent_should_ignore_missing_content_and_invalid_location(self):
        sf, module = self.module({"api_key": "test-key"})
        captured = list()
        responses = [
            None,
            {'code': '200', 'content': None},
            {
                'code': '200',
                'content': json.dumps({'username': "third", 'location': " "}),
            },
        ]

        def new_fetchUrl(url, timeout=0, useragent=None, headers=None):
            return responses.pop(0)

        def new_notifyListeners(self, event):
            captured.append(event)

        sf.fetchUrl = new_fetchUrl
        module.notifyListeners = new_notifyListeners.__get__(module, sfp_xquik)

        for handle in ["first", "second", "third"]:
            module.handleEvent(self.event(f"X: https://x.com/{handle}"))

        self.assertEqual(
            ["RAW_RIR_DATA", "USERNAME"],
            [event.eventType for event in captured]
        )

    def test_handleEvent_should_ignore_non_success_response(self):
        sf, module = self.module({"api_key": "test-key"})
        captured = list()

        def new_fetchUrl(url, timeout=0, useragent=None, headers=None):
            return {'code': '404', 'content': '{}'}

        def new_notifyListeners(self, event):
            captured.append(event)

        sf.fetchUrl = new_fetchUrl
        module.notifyListeners = new_notifyListeners.__get__(module, sfp_xquik)

        self.assertIsNone(module.handleEvent(self.event()))
        self.assertFalse(module.errorState)
        self.assertEqual([], captured)
