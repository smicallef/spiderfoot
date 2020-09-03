# test_spiderfootscanner.py
import unittest
import uuid

from sfscan import SpiderFootScanner


class TestSpiderFootScanner(unittest.TestCase):
    """
    Test SpiderFootScanStatus
    """
    default_options = {
        '_debug': False,
        '__logging': True,
        '__outputfilter': None,
        '__blocknotif': False,
        '_fatalerrors': False,
        '_useragent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0',
        '_dnsserver': '',
        '_fetchtimeout': 5,
        '_internettlds': 'https://publicsuffix.org/list/effective_tld_names.dat',
        '_internettlds_cache': 72,
        '_genericusers': "abuse,admin,billing,compliance,devnull,dns,ftp,hostmaster,inoc,ispfeedback,ispsupport,list-request,list,maildaemon,marketing,noc,no-reply,noreply,null,peering,peering-notify,peering-request,phish,phishing,postmaster,privacy,registrar,registry,root,routing-registry,rr,sales,security,spam,support,sysadmin,tech,undisclosed-recipients,unsubscribe,usenet,uucp,webmaster,www",
        '__version__': '3.3-DEV',
        '__database': 'spiderfoot.test.db',  # note: test database file
        '__webaddr': '127.0.0.1',
        '__webport': 5001,
        '__docroot': '',
        '__modules__': None,
        '_socks1type': '',
        '_socks2addr': '',
        '_socks3port': '',
        '_socks4user': '',
        '_socks5pwd': '',
        '_socks6dns': True,
        '_torctlport': 9051,
        '__logstdout': False
    }

    def test_init_argument_start_false_should_create_a_scan_without_starting_the_scan(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        sfscan = SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, opts, start=False)
        self.assertIsInstance(sfscan, SpiderFootScanner)
        self.assertEqual(sfscan.status, "INITIALIZING")

    def test_init_argument_start_true_should_create_and_start_a_scan(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        sfscan = SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, opts, start=True)
        self.assertIsInstance(sfscan, SpiderFootScanner)
        self.assertEqual(sfscan.status, "FINISHED")

    def test_init_argument_scanName_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootScanner(invalid_type, scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_scanName_as_empty_string_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        with self.assertRaises(ValueError):
            SpiderFootScanner("", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_scanId_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        module_list = ['sfp__stor_db']

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootScanner("example scan name", invalid_type, "spiderfoot.net", "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_scanId_as_empty_string_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = ""
        module_list = ['sfp__stor_db']

        with self.assertRaises(ValueError):
            SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_targetValue_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootScanner("example scan name", scan_id, invalid_type, "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_targetValue_as_empty_string_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        with self.assertRaises(ValueError):
            SpiderFootScanner("example scan name", scan_id, "", "IP_ADDRESS", module_list, self.default_options, start=False)

    def test_init_argument_targetType_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", invalid_type, module_list, self.default_options, start=False)

    def test_init_argument_targetType_as_empty_string_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        target_type = ""
        with self.assertRaises(ValueError):
            SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", target_type, module_list, self.default_options, start=False)

    def test_init_argument_moduleList_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())

        invalid_types = [None, "", dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", invalid_type, self.default_options, start=False)

    def test_init_argument_moduleList_as_empty_list_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        module_list = list()

        with self.assertRaises(ValueError):
            SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, dict(), start=False)

    def test_init_argument_globalOpts_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        invalid_types = [None, "", list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, invalid_type, start=False)

    def test_init_argument_globalOpts_as_empty_dict_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        with self.assertRaises(ValueError):
            SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, dict(), start=False)

    def test_attribute_scanId_should_return_scan_id_as_a_string(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        sfscan = SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, opts, start=False)
        self.assertIsInstance(sfscan, SpiderFootScanner)

        get_id = sfscan.scanId
        self.assertIsInstance(get_id, str)
        self.assertEqual(scan_id, get_id)

    def test_attribute_status_should_return_status_as_a_string(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        sfscan = SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, opts, start=False)
        self.assertIsInstance(sfscan, SpiderFootScanner)

        status = sfscan.status
        self.assertIsInstance(status, str)


if __name__ == '__main__':
    unittest.main()
