# test_spiderfoot_module_loading.py
import os
import pytest
import unittest

from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestSpiderFootModuleLoading(unittest.TestCase):
    """
    Test SpiderFoot module loading
    """

    @staticmethod
    def load_modules(sf):
        # Go through each module in the modules directory with a .py extension
        sfModules = dict()
        mod_dir = sf.myPath() + '/modules/'
        for filename in os.listdir(mod_dir):
            if not filename.startswith("sfp_"):
                continue
            if not filename.endswith(".py"):
                continue
            # Skip the module template and debugging modules
            if filename == "sfp_template.py" or filename == 'sfp_stor_print.py':
                continue

            modName = filename.split('.')[0]

            # Load and instantiate the module
            sfModules[modName] = dict()
            mod = __import__('modules.' + modName, globals(), locals(), [modName])
            sfModules[modName]['object'] = getattr(mod, modName)()
            sfModules[modName]['name'] = sfModules[modName]['object'].meta['name']
            sfModules[modName]['cats'] = sfModules[modName]['object'].meta.get('categories', list())
            sfModules[modName]['group'] = sfModules[modName]['object'].meta.get('useCases', list())
            sfModules[modName]['labels'] = sfModules[modName]['object'].meta.get('flags', list())
            sfModules[modName]['descr'] = sfModules[modName]['object'].meta['summary']
            sfModules[modName]['provides'] = sfModules[modName]['object'].producedEvents()
            sfModules[modName]['consumes'] = sfModules[modName]['object'].watchedEvents()
            sfModules[modName]['meta'] = sfModules[modName]['object'].meta
            if hasattr(sfModules[modName]['object'], 'opts'):
                sfModules[modName]['opts'] = sfModules[modName]['object'].opts
            if hasattr(sfModules[modName]['object'], 'optdescs'):
                sfModules[modName]['optdescs'] = sfModules[modName]['object'].optdescs

        return sfModules

    def test_module_use_cases_are_valid(self):
        sf = SpiderFoot(self.default_options)
        valid_use_cases = ["Footprint", "Passive", "Investigate"]

        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            if module in ["sfp__stor_db", "sfp__stor_stdout"]:
                continue

            self.assertTrue(m.get('group'))

            for group in m.get('group', list()):
                self.assertIn(group, valid_use_cases)

    def test_module_labels_are_valid(self):
        sf = SpiderFoot(self.default_options)
        valid_labels = ["errorprone", "tor", "slow", "invasive", "apikey", "tool"]

        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            for label in m.get('labels', list()):
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

    @unittest.skip("some modules are missing API key instructions")
    def test_modules_with_api_key_have_apiKeyInstructions(self):
        sf = SpiderFoot(self.default_options)
        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            if module in ["sfp__stor_db", "sfp__stor_stdout"]:
                continue

            self.assertTrue(m.get('meta'))
            self.assertIsInstance(m.get('meta'), dict)

            meta = m.get('meta')

            if 'dataSource' in meta and 'apikey' in m.get('labels'):
                self.assertIsInstance(meta.get('dataSource').get('apiKeyInstructions'), list)
                self.assertTrue(meta.get('dataSource').get('apiKeyInstructions'))

    def test_modules_with_api_key_options_have_apikey_label(self):
        sf = SpiderFoot(self.default_options)
        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            for opt in m.get('opts'):
                if "api_key" in opt:
                    self.assertTrue("apikey" in m.get('labels'))

    def test_modules_with_invasive_flag_are_not_in_passive_use_case(self):
        sf = SpiderFoot(self.default_options)
        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            if "Passive" in m.get('group'):
                self.assertTrue("invasive" not in m.get('labels', list()))

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

            if module in ["sfp__stor_db", "sfp__stor_stdout"]:
                continue

            self.assertTrue(m.get('cats'))
            self.assertTrue(m.get('group'))
            self.assertTrue(m.get('provides'))
