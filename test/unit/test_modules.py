# test_modules.py
import os
import pytest
import unittest

from sflib import SpiderFoot
from spiderfoot import SpiderFootDb
from spiderfoot import SpiderFootHelpers


@pytest.mark.usefixtures
class TestSpiderFootModuleLoading(unittest.TestCase):
    """
    Test SpiderFoot module loading
    """

    @staticmethod
    def load_modules(sf):
        mod_dir = os.path.dirname(os.path.abspath(__file__)) + '/../../modules/'
        return SpiderFootHelpers.loadModulesAsDict(mod_dir, ['sfp_template.py'])

    def test_module_use_cases_are_valid(self):
        sf = SpiderFoot(self.default_options)
        valid_use_cases = ["Footprint", "Passive", "Investigate"]

        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            for group in m.get('group'):
                self.assertIn(group, valid_use_cases)

    def test_module_labels_are_valid(self):
        sf = SpiderFoot(self.default_options)
        valid_labels = ["errorprone", "tor", "slow", "invasive", "apikey", "tool"]

        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            for label in m.get('labels'):
                self.assertIn(label, valid_labels)

    def test_module_categories_are_valid(self):
        sf = SpiderFoot(self.default_options)
        valid_categories = ["Content Analysis", "Crawling and Scanning", "DNS",
                            "Leaks, Dumps and Breaches", "Passive DNS",
                            "Public Registries", "Real World", "Reputation Systems",
                            "Search Engines", "Secondary Networks", "Social Media"]

        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            self.assertIsInstance(m.get('cats'), list)
            self.assertTrue(len(m.get('cats')) <= 1)

            if module in ["sfp__stor_db", "sfp__stor_stdout"]:
                continue

            for cat in m.get('cats', list()):
                self.assertIn(cat, valid_categories)

    def test_module_model_is_valid(self):
        sf = SpiderFoot(self.default_options)
        valid_models = [
            "COMMERCIAL_ONLY",
            "FREE_AUTH_LIMITED",
            "FREE_AUTH_UNLIMITED",
            "FREE_NOAUTH_LIMITED",
            "FREE_NOAUTH_UNLIMITED",
            "PRIVATE_ONLY",
        ]

        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            meta = m.get('meta')

            self.assertTrue(meta)
            self.assertIsInstance(meta, dict)

            data_source = meta.get('dataSource')

            if not data_source:
                continue

            self.assertIsInstance(data_source, dict)
            model = data_source.get('model')
            self.assertIsInstance(model, str)
            self.assertIn(model, valid_models)

    def test_modules_with_api_key_have_apiKeyInstructions(self):
        sf = SpiderFoot(self.default_options)
        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            self.assertTrue(m.get('meta'))
            self.assertIsInstance(m.get('meta'), dict)

            meta = m.get('meta')

            if 'apikey' in m.get('labels'):
                self.assertIn('dataSource', meta)
                self.assertIsInstance(meta.get('dataSource').get('apiKeyInstructions'), list)
                self.assertTrue(meta.get('dataSource').get('apiKeyInstructions'))

    def test_modules_with_api_key_options_have_apikey_label(self):
        sf = SpiderFoot(self.default_options)
        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            for opt in m.get('opts'):
                if "api_key" in opt:
                    self.assertIn("apikey", m.get('labels'))

    def test_modules_with_invasive_flag_are_not_in_passive_use_case(self):
        sf = SpiderFoot(self.default_options)
        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            if "Passive" in m.get('group'):
                self.assertNotIn("invasive", m.get('labels', list()))

    def test_module_watched_events_are_valid(self):
        sf = SpiderFoot(self.default_options)
        sf.dbh = SpiderFootDb(self.default_options, True)

        valid_events = []
        for event in sf.dbh.eventTypes():
            valid_events.append(event[1])

        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            for watched_event in m.get('consumes'):
                if watched_event == '*':
                    continue
                self.assertIn(watched_event, valid_events)

    def test_module_produced_events_are_valid(self):
        sf = SpiderFoot(self.default_options)
        sf.dbh = SpiderFootDb(self.default_options, True)

        valid_events = []
        for event in sf.dbh.eventTypes():
            valid_events.append(event[1])

        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            provides = m.get('provides')
            if not provides:
                continue

            for produced_event in provides:
                self.assertIn(produced_event, valid_events)

    def test_each_module_option_has_a_description(self):
        sf = SpiderFoot(self.default_options)
        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            if module in ["sfp__stor_db", "sfp__stor_stdout"]:
                continue

            # check len(options) == len(option descriptions)
            if m.get('opts'):
                self.assertEqual(f"{module} opts: {len(m.get('opts').keys())}", f"{module} opts: {len(m.get('optdescs').keys())}")

    def test_required_module_properties_are_present_and_valid(self):
        sf = SpiderFoot(self.default_options)
        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            self.assertTrue(m.get('object'))
            self.assertTrue(m.get('name'))
            self.assertTrue(m.get('meta'))
            self.assertTrue(m.get('descr'))
            self.assertTrue(m.get('consumes'))
            self.assertIsInstance(m.get('cats'), list)
            self.assertIsInstance(m.get('labels'), list)
            self.assertIsInstance(m.get('provides'), list)
            self.assertIsInstance(m.get('consumes'), list)
            self.assertIsInstance(m.get('meta'), dict)

            # output modules do not have use cases, categories, produced events, data source, etc
            if module in ["sfp__stor_db", "sfp__stor_stdout"]:
                continue

            self.assertTrue(m.get('cats'))
            self.assertTrue(m.get('group'))
            self.assertTrue(m.get('provides'))

            meta = m.get('meta')

            # not all modules will have a data source (sfp_dnsresolve, sfp_dnscommonsrv, etc)
            if meta.get('dataSource'):
                self.assertIsInstance(meta.get('dataSource'), dict)
                self.assertTrue(meta.get('dataSource').get('website'))
                self.assertTrue(meta.get('dataSource').get('model'))
                # self.assertTrue(meta.get('dataSource').get('favIcon'))
                # self.assertTrue(meta.get('dataSource').get('logo'))
                # self.assertTrue(meta.get('dataSource').get('references'))
                # self.assertTrue(meta.get('dataSource').get('description'))

            if module.startswith('sfp_tool_'):
                self.assertIsInstance(meta.get('toolDetails'), dict)
                self.assertTrue(meta.get('toolDetails').get('name'))
                self.assertTrue(meta.get('toolDetails').get('description'))
                self.assertTrue(meta.get('toolDetails').get('website'))
                self.assertTrue(meta.get('toolDetails').get('repository'))
