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

    valid_events = [
        'ACCOUNT_EXTERNAL_OWNED',
        'ACCOUNT_EXTERNAL_OWNED_COMPROMISED',
        'ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED',
        'AFFILIATE_EMAILADDR',
        'AFFILIATE_INTERNET_NAME',
        'AFFILIATE_INTERNET_NAME_HIJACKABLE',
        'AFFILIATE_INTERNET_NAME_UNRESOLVED',
        'AFFILIATE_IPADDR',
        'AFFILIATE_WEB_CONTENT',
        'AFFILIATE_DOMAIN_NAME',
        'AFFILIATE_DOMAIN_UNREGISTERED',
        'AFFILIATE_COMPANY_NAME',
        'AFFILIATE_DOMAIN_WHOIS',
        'AFFILIATE_DESCRIPTION_CATEGORY',
        'AFFILIATE_DESCRIPTION_ABSTRACT',
        'APPSTORE_ENTRY',
        'CLOUD_STORAGE_BUCKET',
        'CLOUD_STORAGE_BUCKET_OPEN',
        'COMPANY_NAME',
        'CREDIT_CARD_NUMBER',
        'BASE64_DATA',
        'BITCOIN_ADDRESS',
        'BITCOIN_BALANCE',
        'BGP_AS_OWNER',
        'BGP_AS_MEMBER',
        'BLACKLISTED_IPADDR',
        'BLACKLISTED_AFFILIATE_IPADDR',
        'BLACKLISTED_SUBNET',
        'BLACKLISTED_NETBLOCK',
        'COUNTRY_NAME',
        'CO_HOSTED_SITE',
        'CO_HOSTED_SITE_DOMAIN',
        'CO_HOSTED_SITE_DOMAIN_WHOIS',
        'DARKNET_MENTION_URL',
        'DARKNET_MENTION_CONTENT',
        'DATE_HUMAN_DOB',
        'DEFACED_INTERNET_NAME',
        'DEFACED_IPADDR',
        'DEFACED_AFFILIATE_INTERNET_NAME',
        'DEFACED_COHOST',
        'DEFACED_AFFILIATE_IPADDR',
        'DESCRIPTION_CATEGORY',
        'DESCRIPTION_ABSTRACT',
        'DEVICE_TYPE',
        'DNS_TEXT',
        'DNS_SRV',
        'DNS_SPF',
        'DOMAIN_NAME',
        'DOMAIN_NAME_PARENT',
        'DOMAIN_REGISTRAR',
        'DOMAIN_WHOIS',
        'EMAILADDR',
        'EMAILADDR_COMPROMISED',
        'EMAILADDR_DELIVERABLE',
        'EMAILADDR_DISPOSABLE',
        'EMAILADDR_GENERIC',
        'EMAILADDR_UNDELIVERABLE',
        'ERROR_MESSAGE',
        'ETHEREUM_ADDRESS',
        'ETHEREUM_BALANCE',
        'GEOINFO',
        'HASH',
        'HASH_COMPROMISED',
        'HTTP_CODE',
        'HUMAN_NAME',
        'IBAN_NUMBER',
        'INTERESTING_FILE',
        'INTERESTING_FILE_HISTORIC',
        'JUNK_FILE',
        'INTERNET_NAME',
        'INTERNET_NAME_UNRESOLVED',
        'IP_ADDRESS',
        'IPV6_ADDRESS',
        'LEI',
        'JOB_TITLE',
        'LINKED_URL_INTERNAL',
        'LINKED_URL_EXTERNAL',
        'MALICIOUS_ASN',
        'MALICIOUS_BITCOIN_ADDRESS',
        'MALICIOUS_IPADDR',
        'MALICIOUS_COHOST',
        'MALICIOUS_EMAILADDR',
        'MALICIOUS_INTERNET_NAME',
        'MALICIOUS_AFFILIATE_INTERNET_NAME',
        'MALICIOUS_AFFILIATE_IPADDR',
        'MALICIOUS_NETBLOCK',
        'MALICIOUS_PHONE_NUMBER',
        'MALICIOUS_SUBNET',
        'NETBLOCK_OWNER',
        'NETBLOCK_MEMBER',
        'NETBLOCK_WHOIS',
        'OPERATING_SYSTEM',
        'LEAKSITE_URL',
        'LEAKSITE_CONTENT',
        'PASSWORD_COMPROMISED',
        'PHONE_NUMBER',
        'PHONE_NUMBER_COMPROMISED',
        'PHONE_NUMBER_TYPE',
        'PHYSICAL_ADDRESS',
        'PHYSICAL_COORDINATES',
        'PGP_KEY',
        'PROVIDER_DNS',
        'PROVIDER_JAVASCRIPT',
        'PROVIDER_MAIL',
        'PROVIDER_HOSTING',
        'PROVIDER_TELCO',
        'PUBLIC_CODE_REPO',
        'RAW_RIR_DATA',
        'RAW_DNS_RECORDS',
        'RAW_FILE_META_DATA',
        'SEARCH_ENGINE_WEB_CONTENT',
        'SOCIAL_MEDIA',
        'SIMILARDOMAIN',
        'SIMILARDOMAIN_WHOIS',
        'SOFTWARE_USED',
        'SSL_CERTIFICATE_RAW',
        'SSL_CERTIFICATE_ISSUED',
        'SSL_CERTIFICATE_ISSUER',
        'SSL_CERTIFICATE_MISMATCH',
        'SSL_CERTIFICATE_EXPIRED',
        'SSL_CERTIFICATE_EXPIRING',
        'TARGET_WEB_CONTENT',
        'TARGET_WEB_CONTENT_TYPE',
        'TARGET_WEB_COOKIE',
        'TCP_PORT_OPEN',
        'TCP_PORT_OPEN_BANNER',
        'UDP_PORT_OPEN',
        'UDP_PORT_OPEN_INFO',
        'URL_ADBLOCKED_EXTERNAL',
        'URL_ADBLOCKED_INTERNAL',
        'URL_FORM',
        'URL_FLASH',
        'URL_JAVASCRIPT',
        'URL_WEB_FRAMEWORK',
        'URL_JAVA_APPLET',
        'URL_STATIC',
        'URL_PASSWORD',
        'URL_UPLOAD',
        'URL_FORM_HISTORIC',
        'URL_FLASH_HISTORIC',
        'URL_JAVASCRIPT_HISTORIC',
        'URL_WEB_FRAMEWORK_HISTORIC',
        'URL_JAVA_APPLET_HISTORIC',
        'URL_STATIC_HISTORIC',
        'URL_PASSWORD_HISTORIC',
        'URL_UPLOAD_HISTORIC',
        'USERNAME',
        'VULNERABILITY',
        'WEB_ANALYTICS_ID',
        'WEBSERVER_BANNER',
        'WEBSERVER_HTTPHEADERS',
        'WEBSERVER_STRANGEHEADER',
        'WEBSERVER_TECHNOLOGY',
        'WIFI_ACCESS_POINT',
        'WIKIPEDIA_PAGE_EDIT',
    ]

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
        valid_labels = ["", "errorprone", "tor", "slow", "invasive", "apikey", "tool"]

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

    def test_module_watched_events_are_valid(self):
        sf = SpiderFoot(self.default_options)
        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            if module in ["sfp__stor_db", "sfp__stor_stdout"]:
                continue

            for watched_event in m.get('consumes'):
                if watched_event == '*':
                    continue
                self.assertTrue(watched_event in self.valid_events)

    def test_module_produced_events_are_valid(self):
        sf = SpiderFoot(self.default_options)
        sfModules = self.load_modules(sf)
        for module in sfModules:
            m = sfModules[module]

            if module in ["sfp__stor_db", "sfp__stor_stdout"]:
                continue

            for produced_event in m.get('provides'):
                self.assertTrue(produced_event in self.valid_events)

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
