# test_spiderfootscanner.py
import pytest
import unittest
import uuid

from sfscan import SpiderFootScanner


@pytest.mark.usefixtures
class TestSpiderFootScanner(unittest.TestCase):
    """
    Test SpiderFootScanStatus
    """

    def test_init_argument_start_false_should_create_a_scan_without_starting_the_scan(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts, start=True)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        sfscan = SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "INTERNET_NAME", module_list, opts, start=False)
        self.assertIsInstance(sfscan, SpiderFootScanner)
        self.assertEqual(sfscan.status, "INITIALIZING")

    def test_init_argument_start_true_with_no_valid_modules_should_set_scanstatus_to_failed(self):
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['invalid module']

        sfscan = SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "INTERNET_NAME", module_list, opts, start=True)
        self.assertIsInstance(sfscan, SpiderFootScanner)
        self.assertEqual(sfscan.status, "ERROR-FAILED")

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

    def test_init_argument_targetType_invalid_value_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        target_type = ""
        with self.assertRaises(ValueError):
            SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", target_type, module_list, self.default_options, start=False)

        target_type = "INVALID_TARGET_TYPE"
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
            SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, self.default_options, start=False)

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

    def test_init_argument_globalOpts_proxy_invalid_proxy_type_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        opts = self.default_options
        opts['_socks1type'] = 'invalid proxy type'
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        with self.assertRaises(ValueError):
            SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, opts, start=False)

    def test_init_argument_globalOpts_proxy_type_without_host_should_raise_ValueError(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        opts = self.default_options
        opts['_socks1type'] = 'HTTP'
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        with self.assertRaises(ValueError):
            SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, opts, start=False)

    def test_init_argument_globalOpts_proxy_should_set_proxy(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        opts = self.default_options
        opts['_socks1type'] = 'HTTP'
        opts['_socks2addr'] = '127.0.0.1'
        opts['_socks3port'] = '8080'
        opts['_socks4user'] = 'user'
        opts['_socks5pwd'] = 'password'
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, opts, start=False)

        self.assertEqual('TBD', 'TBD')

    def test_init_argument_globalOpts_proxy_without_port_should_set_proxy(self):
        """
        Test __init__(self, scanName, scanId, scanTarget, targetType, moduleList, globalOpts)
        """
        opts = self.default_options
        opts['_socks1type'] = 'HTTP'
        opts['_socks2addr'] = '127.0.0.1'
        opts['_socks3port'] = ''
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, opts, start=False)

        self.assertEqual('TBD', 'TBD')

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

    def test__setStatus_argument_status_of_invalid_type_should_raise_TypeError(self):
        """
        Test __setStatus(self, status, started=None, ended=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        sfscan = SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, opts, start=False)

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    sfscan._SpiderFootScanner__setStatus(invalid_type)

    def test__setStatus_argument_status_with_blank_value_should_raise_ValueError(self):
        """
        Test __setStatus(self, status, started=None, ended=None)
        """
        opts = self.default_options
        opts['__modules__'] = dict()
        scan_id = str(uuid.uuid4())
        module_list = ['sfp__stor_db']

        sfscan = SpiderFootScanner("example scan name", scan_id, "spiderfoot.net", "IP_ADDRESS", module_list, opts, start=False)
        with self.assertRaises(ValueError):
            sfscan._SpiderFootScanner__setStatus("example invalid scan status")
