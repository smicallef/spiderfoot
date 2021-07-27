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

    def test_module_loading(self):
        sf = SpiderFoot(self.default_options)

        # Go through each module in the modules directory with a .py extension
        sfModules = dict()
        mod_dir = sf.myPath() + '/modules/'
        for filename in os.listdir(mod_dir):
            if filename.startswith("sfp_") and filename.endswith(".py"):
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

        self.assertTrue(len(sfModules.keys()))

        valid_use_cases = ["Footprint", "Passive", "Investigate"]
        valid_categories = ["Content Analysis", "Crawling and Scanning", "DNS",
                            "Leaks, Dumps and Breaches", "Passive DNS",
                            "Public Registries", "Real World", "Reputation Systems",
                            "Search Engines", "Secondary Networks", "Social Media"]

        for module in sfModules:
            m = sfModules[module]

            self.assertTrue(m.get('object'))
            self.assertTrue(m.get('name'))
            self.assertTrue(m.get('meta'))
            self.assertIsInstance(m.get('cats'), list)
            # self.assertTrue(m.get('group'))
            self.assertIsInstance(m.get('labels'), list)
            self.assertTrue(m.get('descr'))
            # self.assertTrue(m.get('provides'))
            self.assertIsInstance(m.get('provides'), list)
            self.assertTrue(m.get('consumes'))
            self.assertIsInstance(m.get('consumes'), list)
            self.assertIsInstance(m.get('meta'), dict)

            # skip debugging and output modules
            if module in ["sfp__stor_db", "sfp__stor_stdout"]:
                continue

            for cat in m.get('group', list()):
                self.assertIn(cat, valid_use_cases)

            for cat in m.get('cats', list()):
                self.assertIn(cat, valid_categories)

            self.assertTrue(m.get('name'))
            self.assertTrue(m.get('descr'))

            # check len(options) == len(option descriptions)
            if m.get('opts'):
                self.assertEqual("%s opts: %s" % (module, len(m.get('opts').keys())), "%s opts: %s" % (module, len(m.get('optdescs').keys())))
