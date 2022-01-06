# test_spiderfoot.py
import pytest
import unittest

from sflib import SpiderFoot


@pytest.mark.usefixtures
class TestSpiderFoot(unittest.TestCase):
    """
    Test SpiderFoot
    """

    default_modules = [
        "sfp_binstring",
        "sfp_company",
        "sfp_cookie",
        "sfp_countryname",
        "sfp_creditcard",
        "sfp_email",
        "sfp_errors",
        "sfp_ethereum",
        "sfp_filemeta",
        "sfp_hashes",
        "sfp_iban",
        "sfp_names",
        "sfp_pageinfo",
        "sfp_phone",
        "sfp_webanalytics"
    ]

    test_tlds = "// ===BEGIN ICANN DOMAINS===\n\ncom\nnet\norg\n\n// // ===END ICANN DOMAINS===\n"

    def test_init_argument_options_of_invalid_type_should_raise_TypeError(self):
        """
        Test __init__(self, options):
        """
        invalid_types = [None, "", list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type), self.assertRaises(TypeError):
                SpiderFoot(invalid_type)

    def test_init_argument_options_with_empty_dict(self):
        """
        Test __init__(self, options):
        """
        sf = SpiderFoot(dict())
        self.assertIsInstance(sf, SpiderFoot)

    def test_init_argument_options_with_default_options(self):
        """
        Test __init__(self, options):
        """
        sf = SpiderFoot(self.default_options)
        self.assertIsInstance(sf, SpiderFoot)

    def test_attribute_dbh(self):
        sf = SpiderFoot(dict())

        sf.dbh = 'new handle'
        self.assertEqual('new handle', sf.dbh)

    def test_attribute_scanId(self):
        sf = SpiderFoot(dict())

        sf.scanId = 'new guid'
        self.assertEqual('new guid', sf.scanId)

    def test_attribute_socksProxy(self):
        sf = SpiderFoot(dict())

        sf.socksProxy = 'new socket'
        self.assertEqual('new socket', sf.socksProxy)

    def test_optValueToData_should_return_data_as_string(self):
        """
        Test optValueToData(self, val)
        """
        sf = SpiderFoot(self.default_options)

        test_string = "example string"
        opt_data = sf.optValueToData(test_string)
        self.assertIsInstance(opt_data, str)
        self.assertEqual(test_string, opt_data)

    def test_optValueToData_argument_val_filename_should_return_file_contents_as_string(self):
        """
        Test optValueToData(self, val)
        """
        sf = SpiderFoot(self.default_options)

        test_string = "@VERSION"
        opt_data = sf.optValueToData(test_string)
        self.assertIsInstance(opt_data, str)
        self.assertTrue(opt_data.startswith("SpiderFoot"))

    def test_optValueToData_argument_val_invalid_type_should_return_None(self):
        """
        Test optValueToData(self, val)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, list(), int(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                opt_data = sf.optValueToData(invalid_type)
                self.assertEqual(opt_data, None)

    def test_error(self):
        """
        Test error(self, error):
        """
        sf = SpiderFoot(self.default_options)

        sf.error(None)
        self.assertEqual('TBD', 'TBD')

    def test_fatal_should_exit(self):
        """
        Test fatal(self, error)
        """
        sf = SpiderFoot(self.default_options)

        with self.assertRaises(SystemExit) as cm:
            sf.fatal(None)

        self.assertEqual(cm.exception.code, -1)

    def test_status(self):
        """
        Test status(self, message)
        """
        sf = SpiderFoot(self.default_options)

        sf.status(None)
        self.assertEqual('TBD', 'TBD')

    def test_info(self):
        """
        Test info(self, message)
        """
        sf = SpiderFoot(self.default_options)

        sf.info(None)
        self.assertEqual('TBD', 'TBD')

    def test_debug(self):
        """
        Test debug(self, message)
        """
        sf = SpiderFoot(self.default_options)

        sf.debug(None)
        self.assertEqual('TBD', 'TBD')

    def test_my_path_should_return_a_string(self):
        """
        Test myPath(self)
        """
        sf = SpiderFoot(dict())

        path = sf.myPath()
        self.assertIsInstance(path, str)

    def test_hash_string_should_return_a_string(self):
        """
        Test hashstring(self, string)
        """
        sf = SpiderFoot(dict())

        hash_string = sf.hashstring('example string')
        self.assertIsInstance(hash_string, str)
        self.assertEqual("aedfb92b3053a21a114f4f301a02a3c6ad5dff504d124dc2cee6117623eec706", hash_string)

    def test_cache_get_should_return_a_string(self):
        """
        Test cachePut(self, label, data)
        Test cacheGet(self, label, timeoutHrs)
        """
        sf = SpiderFoot(dict())

        label = 'test-cache-label'
        data = 'test-cache-data'

        sf.cachePut(label, data)

        cache_get = sf.cacheGet(label, sf.opts.get('cacheperiod', 0))
        self.assertIsInstance(cache_get, str)
        self.assertEqual(data, cache_get)

    def test_config_serialize_invalid_opts_should_raise(self):
        """
        Test configSerialize(self, opts, filterSystem=True)
        """
        sf = SpiderFoot(dict())

        with self.assertRaises(TypeError):
            sf.configSerialize(None, None)

    def test_config_serialize_should_return_a_dict(self):
        """
        Test configSerialize(self, opts, filterSystem=True)
        """
        sf = SpiderFoot(dict())

        config = sf.configSerialize(dict(), None)
        self.assertIsInstance(config, dict)

    def test_config_unserialize_invalid_opts_should_raise(self):
        """
        Test configUnserialize(self, opts, referencePoint, filterSystem=True)
        """
        sf = SpiderFoot(dict())

        with self.assertRaises(TypeError):
            sf.configUnserialize(None, dict(), None)

    def test_config_unserialize_invalid_reference_point_should_raise(self):
        """
        Test configUnserialize(self, opts, referencePoint, filterSystem=True)
        """
        sf = SpiderFoot(dict())

        with self.assertRaises(TypeError):
            sf.configUnserialize(dict(), None, None)

    def test_config_unserialize_should_return_a_dict(self):
        """
        Test configUnserialize(self, opts, referencePoint, filterSystem=True)
        """
        sf = SpiderFoot(dict())

        config = sf.configUnserialize(dict(), dict(), True)
        self.assertIsInstance(config, dict)

    def test_cache_get_invalid_label_should_return_none(self):
        """
        Test cacheGet(self, label, timeoutHrs)
        """
        sf = SpiderFoot(dict())

        cache_get = sf.cacheGet('', sf.opts.get('cacheperiod', 0))
        self.assertEqual(None, cache_get)

    def test_cache_get_invalid_timeout_should_return_none(self):
        """
        Test cacheGet(self, label, timeoutHrs)
        """
        sf = SpiderFoot(dict())

        cache_get = sf.cacheGet('', None)
        self.assertEqual(None, cache_get)

    def test_modulesProducing_argument_events_should_return_a_list(self):
        """
        Test modulesProducing(self, events)
        """
        sf = SpiderFoot(self.default_options)

        events = ['IP_ADDRESS', 'DOMAIN_NAME', 'INTERNET_NAME']

        modules_producing = sf.modulesProducing(events)
        self.assertIsInstance(modules_producing, list)

    def test_modulesProducing_argument_events_with_empty_value_should_return_a_list(self):
        """
        Test modulesProducing(self, events)
        """
        sf = SpiderFoot(dict())

        modules_producing = sf.modulesProducing(list())
        self.assertIsInstance(modules_producing, list)

    def test_modulesConsuming_argument_events_should_return_a_list(self):
        """
        Test modulesConsuming(self, events)
        """
        sf = SpiderFoot(self.default_options)

        events = ['IP_ADDRESS', 'DOMAIN_NAME', 'INTERNET_NAME']

        modules_consuming = sf.modulesConsuming(events)
        self.assertIsInstance(modules_consuming, list)

    def test_modulesConsuming_argument_events_with_empty_value_should_return_a_list(self):
        """
        Test modulesConsuming(self, events)
        """
        sf = SpiderFoot(dict())

        modules_consuming = sf.modulesConsuming(list())
        self.assertIsInstance(modules_consuming, list)

    def test_eventsFromModules_argument_modules_with_empty_value_should_return_a_list(self):
        """
        Test eventsFromModules(self, modules)
        """
        sf = SpiderFoot(self.default_options)

        events_from_modules = sf.eventsFromModules(list())
        self.assertIsInstance(events_from_modules, list)

    def test_eventsFromModules_argument_modules_should_return_events(self):
        """
        Test eventsFromModules(self, modules)
        """
        sf = SpiderFoot(self.default_options)

        events_from_modules = sf.eventsFromModules(self.default_modules)
        self.assertIsInstance(events_from_modules, list)

    def test_eventsToModules_argument_modules_with_empty_value_should_return_a_list(self):
        """
        Test eventsToModules(self, modules)
        """
        sf = SpiderFoot(self.default_options)

        events_to_modules = sf.eventsToModules(list())
        self.assertIsInstance(events_to_modules, list)

    def test_eventsToModules_argument_modules_should_return_events(self):
        """
        Test eventsToModules(self, modules)
        """
        sf = SpiderFoot(self.default_options)

        events_to_modules = sf.eventsToModules(self.default_modules)
        self.assertIsInstance(events_to_modules, list)

    def test_url_relative_to_absolute_should_return_a_string(self):
        """
        Test urlRelativeToAbsolute(self, url)
        """
        sf = SpiderFoot(dict())

        relative_url = sf.urlRelativeToAbsolute('/somewhere/else/../../path?param=value#fragment')
        self.assertIsInstance(relative_url, str)
        self.assertEqual('/path?param=value#fragment', relative_url)

    def test_url_base_dir_should_return_a_string(self):
        """
        Test urlBaseDir(self, url)
        """
        sf = SpiderFoot(dict())

        base_dir = sf.urlBaseDir('http://localhost.local/path?param=value#fragment')
        self.assertIsInstance(base_dir, str)
        self.assertEqual('http://localhost.local/', base_dir)

    def test_url_base_url_should_return_a_string(self):
        """
        Test urlBaseUrl(self, url)
        """
        sf = SpiderFoot(dict())

        base_url = sf.urlBaseUrl('http://localhost.local/path?param=value#fragment')
        self.assertIsInstance(base_url, str)
        self.assertEqual('http://localhost.local', base_url)

    def test_url_fqdn_should_return_a_string(self):
        """
        Test urlFQDN(self, url)
        """
        sf = SpiderFoot(dict())

        fqdn = sf.urlFQDN('http://localhost.local')
        self.assertIsInstance(fqdn, str)
        self.assertEqual("localhost.local", fqdn)

    def test_domain_keyword_should_return_a_string(self):
        """
        Test domainKeyword(self, domain, tldList)
        """
        sf = SpiderFoot(self.default_options)
        sf.opts['_internettlds'] = self.test_tlds

        keyword = sf.domainKeyword('www.spiderfoot.net', sf.opts.get('_internettlds'))
        self.assertIsInstance(keyword, str)
        self.assertEqual('spiderfoot', keyword)

        keyword = sf.domainKeyword('spiderfööt.example', sf.opts.get('_internettlds'))
        self.assertIsInstance(keyword, str)
        self.assertEqual('spiderfööt', keyword)

    def test_domain_keyword_invalid_domain_should_return_none(self):
        """
        Test domainKeyword(self, domain, tldList)
        """
        sf = SpiderFoot(self.default_options)
        sf.opts['_internettlds'] = self.test_tlds

        keyword = sf.domainKeyword("", sf.opts.get('_internettlds'))
        self.assertEqual(None, keyword)
        keyword = sf.domainKeyword([], sf.opts.get('_internettlds'))
        self.assertEqual(None, keyword)
        keyword = sf.domainKeyword(None, sf.opts.get('_internettlds'))
        self.assertEqual(None, keyword)
        keyword = sf.domainKeyword("net", sf.opts.get('_internettlds'))
        self.assertEqual(None, keyword)
        keyword = sf.domainKeyword(".net", sf.opts.get('_internettlds'))
        self.assertEqual(None, keyword)
        keyword = sf.domainKeyword(".", sf.opts.get('_internettlds'))
        self.assertEqual(None, keyword)

    def test_domain_keywords_should_return_a_set(self):
        """
        Test domainKeywords(self, domainList, tldList)
        """
        sf = SpiderFoot(self.default_options)
        sf.opts['_internettlds'] = self.test_tlds

        domain_list = ['www.example.com', 'localhost.local']
        keywords = sf.domainKeywords(domain_list, sf.opts.get('_internettlds'))
        self.assertIsInstance(keywords, set)
        self.assertIn('localhost', keywords)
        self.assertIn('example', keywords)

    def test_domain_keywords_invalid_domainlist_should_return_a_set(self):
        """
        Test domainKeyword(self, domain, tldList)
        """
        sf = SpiderFoot(self.default_options)
        sf.opts['_internettlds'] = self.test_tlds

        keywords = sf.domainKeywords("", sf.opts.get('_internettlds'))
        self.assertIsInstance(keywords, set)
        keywords = sf.domainKeywords([], sf.opts.get('_internettlds'))
        self.assertIsInstance(keywords, set)
        keywords = sf.domainKeywords(None, sf.opts.get('_internettlds'))
        self.assertIsInstance(keywords, set)

    def test_host_domain_invalid_host_should_return_none(self):
        """
        Test hostDomain(self, hostname, tldList)
        """
        sf = SpiderFoot(self.default_options)
        sf.opts['_internettlds'] = self.test_tlds

        host_domain = sf.hostDomain(None, sf.opts.get('_internettlds'))
        self.assertEqual(None, host_domain)

    def test_host_domain_should_return_a_string(self):
        """
        Test hostDomain(self, hostname, tldList)
        """
        sf = SpiderFoot(self.default_options)
        sf.opts['_internettlds'] = self.test_tlds

        host_domain = sf.hostDomain('www.spiderfoot.net', sf.opts.get('_internettlds'))
        self.assertIsInstance(host_domain, str)
        self.assertEqual('spiderfoot.net', host_domain)

        host_domain = sf.hostDomain('spiderfoot.net', sf.opts.get('_internettlds'))
        self.assertIsInstance(host_domain, str)
        self.assertEqual('spiderfoot.net', host_domain)

        host_domain = sf.hostDomain('abc.www.spiderfoot.net', sf.opts.get('_internettlds'))
        self.assertIsInstance(host_domain, str)
        self.assertEqual('spiderfoot.net', host_domain)

    def test_host_domain_invalid_tldlist_should_return_none(self):
        """
        Test hostDomain(self, hostname, tldList)
        """
        sf = SpiderFoot(dict())

        host_domain = sf.hostDomain('spiderfoot.net', None)
        self.assertEqual(None, host_domain)

    def test_is_domain_valid_domain_should_return_true(self):
        """
        Test isDomain(self, hostname, tldList)
        """
        sf = SpiderFoot(self.default_options)
        sf.opts['_internettlds'] = self.test_tlds

        is_domain = sf.isDomain('spiderfoot.net', sf.opts.get('_internettlds'))
        self.assertIsInstance(is_domain, bool)
        self.assertTrue(is_domain)

    def test_is_domain_invalid_domain_should_return_false(self):
        """
        Test isDomain(self, hostname, tldList)
        """
        sf = SpiderFoot(self.default_options)
        sf.opts['_internettlds'] = self.test_tlds

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                is_domain = sf.isDomain(invalid_type, sf.opts.get('_internettlds'))
                self.assertIsInstance(is_domain, bool)
                self.assertFalse(is_domain)

        is_domain = sf.isDomain("local", sf.opts.get('_internettlds'))
        self.assertIsInstance(is_domain, bool)
        self.assertFalse(is_domain)

        is_domain = sf.isDomain("spiderfoot.net\n.com", sf.opts.get('_internettlds'))
        self.assertIsInstance(is_domain, bool)
        self.assertFalse(is_domain)

    def test_is_domain_invalid_tldlist_should_return_false(self):
        """
        Test isDomain(self, hostname, tldList)
        """
        sf = SpiderFoot(self.default_options)

        is_domain = sf.isDomain('spiderfoot.net', None)
        self.assertIsInstance(is_domain, bool)
        self.assertFalse(is_domain)

    def test_is_domain_invalid_tld_should_return_false(self):
        """
        Test isDomain(self, hostname, tldList)
        """
        sf = SpiderFoot(self.default_options)
        sf.opts['_internettlds'] = self.test_tlds

        is_domain = sf.isDomain('spiderfoot.not_a_tld', sf.opts.get('_internettlds'))
        self.assertIsInstance(is_domain, bool)
        self.assertFalse(is_domain)

    def test_valid_host_invalid_tldlist_should_return_false(self):
        """
        Test validHost(self, hostname, tldList)
        """
        sf = SpiderFoot(self.default_options)

        is_host = sf.validHost('spiderfoot.net', None)
        self.assertIsInstance(is_host, bool)
        self.assertFalse(is_host)

    def test_valid_host_valid_host_should_return_true(self):
        """
        Test validHost(self, hostname, tldList)
        """
        sf = SpiderFoot(self.default_options)
        sf.opts['_internettlds'] = self.test_tlds

        is_host = sf.validHost('spiderfoot.net', sf.opts.get('_internettlds'))
        self.assertIsInstance(is_host, bool)
        self.assertTrue(is_host)

    def test_valid_host_invalid_host_should_return_false(self):
        """
        Test validHost(self, hostname, tldList)
        """
        sf = SpiderFoot(self.default_options)
        sf.opts['_internettlds'] = self.test_tlds

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                is_valid = sf.validHost(invalid_type, sf.opts.get('_internettlds'))
                self.assertIsInstance(is_valid, bool)
                self.assertFalse(is_valid)

        is_valid = sf.validHost("local", sf.opts.get('_internettlds'))
        self.assertIsInstance(is_valid, bool)
        self.assertFalse(is_valid)

        is_valid = sf.validHost('something.gif', sf.opts.get('_internettlds'))
        self.assertIsInstance(is_valid, bool)
        self.assertFalse(is_valid)

        is_valid = sf.validHost(".", sf.opts.get('_internettlds'))
        self.assertIsInstance(is_valid, bool)
        self.assertFalse(is_valid)

        is_valid = sf.validHost("spiderfoot.net\n.com", sf.opts.get('_internettlds'))
        self.assertIsInstance(is_valid, bool)
        self.assertFalse(is_valid)

    def test_valid_ip_should_return_a_boolean(self):
        """
        Test validIP(self, address)
        """
        sf = SpiderFoot(dict())

        valid_ip = sf.validIP('0.0.0.0')
        self.assertIsInstance(valid_ip, bool)
        self.assertTrue(valid_ip)

    def test_valid_ip6_should_return_a_boolean(self):
        """
        Test validIP6(self, address)
        """
        sf = SpiderFoot(dict())

        valid_ip6 = sf.validIP6('::1')
        self.assertIsInstance(valid_ip6, bool)
        self.assertTrue(valid_ip6)

    def test_valid_ip_network_should_return_a_boolean(self):
        """
        Test validIpNetwork(self, cidr)
        """
        sf = SpiderFoot(dict())

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                valid_ip_network = sf.validIpNetwork(invalid_type)
                self.assertIsInstance(valid_ip_network, bool)
                self.assertFalse(valid_ip_network)

        valid_ip_network = sf.validIpNetwork("/")
        self.assertIsInstance(valid_ip_network, bool)
        self.assertFalse(valid_ip_network)

        valid_ip_network = sf.validIpNetwork('0.0.0.0/0')
        self.assertIsInstance(valid_ip_network, bool)
        self.assertTrue(valid_ip_network)

    def test_isPublicIpAddress_should_return_a_boolean(self):
        """
        Test isPublicIpAddress(self, ip)
        """
        sf = SpiderFoot(dict())

        self.assertTrue(sf.isPublicIpAddress('1.1.1.1'))

        ips = [
            'invalid ip address',
            '0.0.0.0',
            '127.0.0.1',
            '10.1.1.1',
            '172.16.1.1',
            '192.168.1.1',
            '255.240.0.0',
            '172.31.255.255',
            '224.0.1.0',
            '255.255.255.255',
            '169.254.0.1',
            '253.0.0.1',
            '::1',
            'ff00::1',
        ]
        for ip in ips:
            with self.subTest(ip=ip):
                self.assertFalse(sf.isPublicIpAddress(ip))

    def test_valid_email_should_return_a_boolean(self):
        """
        Test validEmail(self, email)
        """
        sf = SpiderFoot(dict())

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                valid_email = sf.validEmail(invalid_type)
                self.assertIsInstance(valid_email, bool)
                self.assertFalse(valid_email)

        valid_email = sf.validEmail('%@localhost.local')
        self.assertIsInstance(valid_email, bool)
        self.assertFalse(valid_email)

        valid_email = sf.validEmail('...@localhost.local')
        self.assertIsInstance(valid_email, bool)
        self.assertFalse(valid_email)

        valid_email = sf.validEmail('root@localhost.local\n.com')
        self.assertIsInstance(valid_email, bool)
        self.assertFalse(valid_email)

        valid_email = sf.validEmail('root@localhost')
        self.assertIsInstance(valid_email, bool)
        self.assertFalse(valid_email)

        valid_email = sf.validEmail('root@localhost.local')
        self.assertIsInstance(valid_email, bool)
        self.assertTrue(valid_email)

    def test_validPhoneNumber_should_return_a_boolean(self):
        """
        Test validPhoneNumber(self, phone)
        """
        sf = SpiderFoot(dict())

        invalid_types = [None, "", list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                valid_phone = sf.validPhoneNumber(invalid_type)
                self.assertIsInstance(valid_phone, bool)
                self.assertFalse(valid_phone)

        valid_phone = sf.validPhoneNumber('+1234567890')
        self.assertIsInstance(valid_phone, bool)
        self.assertFalse(valid_phone)

        valid_phone = sf.validPhoneNumber('+12345678901234567890')
        self.assertIsInstance(valid_phone, bool)
        self.assertFalse(valid_phone)

        valid_phone = sf.validPhoneNumber('+12345678901')
        self.assertIsInstance(valid_phone, bool)
        self.assertTrue(valid_phone)

    def test_normalize_dns(self):
        """
        Test normalizeDNS(self, res)
        """
        sf = SpiderFoot(self.default_options)

        dns = sf.normalizeDNS(["example.local.", ["spiderfoot.net."]])
        self.assertIsInstance(dns, list)
        self.assertIn("example.local", dns)
        self.assertIn("spiderfoot.net", dns)

    def test_normalize_dns_should_return_list(self):
        """
        Test normalizeDNS(self, res)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                dns = sf.normalizeDNS(invalid_type)
                self.assertIsInstance(dns, list)

    def test_dictwords_should_return_a_list(self):
        """
        Test dictwords(self)
        """
        sf = SpiderFoot(dict())

        dict_words = sf.dictwords()
        self.assertIsInstance(dict_words, list)

    def test_dictnames_should_return_a_list(self):
        """
        Test dictnames(self)
        """
        sf = SpiderFoot(dict())

        dict_names = sf.dictnames()
        self.assertIsInstance(dict_names, list)

    def test_resolve_host_should_return_list(self):
        """
        Test resolveHost(self, host)
        """
        sf = SpiderFoot(self.default_options)

        addrs = sf.resolveHost('one.one.one.one')
        self.assertIsInstance(addrs, list)
        self.assertTrue(addrs)
        self.assertIn('1.1.1.1', addrs)

        addrs = sf.resolveHost(None)
        self.assertFalse(addrs)
        self.assertIsInstance(addrs, list)

    def test_resolve_ip_should_return_list(self):
        """
        Test resolveIP(self, ipaddr)
        """
        sf = SpiderFoot(self.default_options)

        addrs = sf.resolveIP('1.1.1.1')
        self.assertIsInstance(addrs, list)
        self.assertTrue(addrs)
        self.assertIn('one.one.one.one', addrs)

        addrs = sf.resolveIP('2606:4700:4700::1001')
        self.assertIsInstance(addrs, list)
        self.assertTrue(addrs)
        self.assertIn('one.one.one.one', addrs)

        addrs = sf.resolveIP(None)
        self.assertFalse(addrs)
        self.assertIsInstance(addrs, list)

        addrs = sf.resolveIP([])
        self.assertFalse(addrs)
        self.assertIsInstance(addrs, list)

        addrs = sf.resolveIP("")
        self.assertFalse(addrs)
        self.assertIsInstance(addrs, list)

    def test_resolve_host6_should_return_a_list(self):
        """
        Test resolveHost6(self, hostname)
        """
        sf = SpiderFoot(self.default_options)

        addrs = sf.resolveHost6('one.one.one.one')
        self.assertIsInstance(addrs, list)
        self.assertTrue(addrs)
        # TODO: Re-enable this once GitHub runners support IPv6
        # https://github.com/actions/virtual-environments/issues/668
        # self.assertIn('2606:4700:4700::1001', addrs)
        # self.assertIn('2606:4700:4700::1111', addrs)

        addrs = sf.resolveHost6(None)
        self.assertFalse(addrs)
        self.assertIsInstance(addrs, list)

    def test_validate_ip_should_return_bool(self):
        """
        Test validateIP(self, host, ip)
        """
        sf = SpiderFoot(self.default_options)

        validate_ip = sf.validateIP(None, None)
        self.assertIsInstance(validate_ip, bool)
        self.assertFalse(validate_ip)

        validate_ip = sf.validateIP('one.one.one.one', '1.1.1.1')
        self.assertIsInstance(validate_ip, bool)
        self.assertTrue(validate_ip)

    @unittest.skip("todo")
    def test_safe_socket(self):
        """
        Test safeSocket(self, host, port, timeout)
        """
        sf = SpiderFoot(self.default_options)
        sf.safeSocket(None, None, None)

        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_safe_ssl_socket(self):
        """
        Test safeSSLSocket(self, host, port, timeout)
        """
        sf = SpiderFoot(self.default_options)

        sf.safeSSLSocket(None, None, None, None)
        self.assertEqual('TBD', 'TBD')

    def test_parseHashes_should_return_a_list(self):
        """
        Test parseHashes(self, data)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                hashes = sf.parseHashes(invalid_type)
                self.assertIsInstance(hashes, list)

    def test_parseHashes_argument_data_should_return_hahes(self):
        """
        Test parseHashes(self, data)
        """
        sf = SpiderFoot(self.default_options)

        md5_hash = "e17cff4eb3e8fbe6ca3b83fb47532dba"
        sha1_hash = "f81efbe70f8116fcf3dc4e9b37725dcb949719f5"
        sha256_hash = "7cd444af3d8de9e195b1f1cb55e7b7d9409dcd4648247c853a2f64b7578dc9b7"
        sha512_hash = "a55a2fe120d7d7d6e2ba930e6c56faa30b9d24a3178a0aff1d89312a89d61d8a9d5b7743e3af6b1a318d99974a1145ed76f85aa8c6574074dfb347613ccd3249"

        hashes = sf.parseHashes(f"spiderfoot{md5_hash}spiderfoot{sha1_hash}spiderfoot{sha256_hash}spiderfoot{sha512_hash}spiderfoot")

        self.assertIsInstance(hashes, list)
        self.assertIn(("MD5", md5_hash), hashes)
        self.assertIn(("SHA1", sha1_hash), hashes)
        self.assertIn(("SHA256", sha256_hash), hashes)
        self.assertIn(("SHA512", sha512_hash), hashes)

    def test_parse_credit_cards_should_return_a_list(self):
        """
        Test parseCreditCards(self, data)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                cards = sf.parseCreditCards(invalid_type)
                self.assertIsInstance(cards, list)

        cards = sf.parseCreditCards("spiderfoot4111 1111 1111 1111spiderfoot")
        self.assertIsInstance(cards, list)
        self.assertIn("4111111111111111", cards)

    def test_getCountryCodeDict_should_return_a_dict(self):
        """
        Test getCountryCodeDict(self)
        """
        sf = SpiderFoot(dict())

        country_code_dict = sf.getCountryCodeDict()
        self.assertIsInstance(country_code_dict, dict)

    def test_countryNameFromCountryCode_argument_countryCode_should_return_country_as_a_string(self):
        """
        Test countryNameFromCountryCode(self, countryCode)
        """
        sf = SpiderFoot(dict())

        country_name = sf.countryNameFromCountryCode('US')
        self.assertIsInstance(country_name, str)
        self.assertEqual(country_name, "United States")

    def test_countryNameFromTld_argument_tld_should_return_country_as_a_string(self):
        """
        Test countryNameFromTld(self, tld)
        """
        sf = SpiderFoot(dict())

        tlds = ['com', 'net', 'org', 'gov', 'mil']
        for tld in tlds:
            with self.subTest(tld=tld):
                country_name = sf.countryNameFromTld(tld)
                self.assertIsInstance(country_name, str)
                self.assertEqual(country_name, "United States")

    def test_parse_iban_numbers_should_return_a_list(self):
        """
        Test parseIBANNumbers(self, data)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                ibans = sf.parseIBANNumbers(invalid_type)
                self.assertIsInstance(ibans, list)

        # Example IBANS from https://www.iban.com/structure
        ibans = [
            "AL35202111090000000001234567",
            "AD1400080001001234567890",
            "AT483200000012345864",
            "AZ96AZEJ00000000001234567890",
            "BH02CITI00001077181611",
            "BY86AKBB10100000002966000000",
            "BE71096123456769",
            "BA393385804800211234",
            "BR1500000000000010932840814P2",
            "BG18RZBB91550123456789",
            "CR23015108410026012345",
            "HR1723600001101234565",
            "CY21002001950000357001234567",
            "CZ5508000000001234567899",
            "DK9520000123456789",
            "DO22ACAU00000000000123456789",
            "EG800002000156789012345180002",
            "SV43ACAT00000000000000123123",
            "EE471000001020145685",
            "FO9264600123456789",
            "FI1410093000123458",
            "FR7630006000011234567890189",
            "GE60NB0000000123456789",
            "DE75512108001245126199",
            "GI04BARC000001234567890",
            "GR9608100010000001234567890",
            "GL8964710123456789",
            "GT20AGRO00000000001234567890",
            "VA59001123000012345678",
            "HU93116000060000000012345676",
            "IS750001121234563108962099",
            "IQ20CBIQ861800101010500",
            "IE64IRCE92050112345678",
            "IL170108000000012612345",
            "IT60X0542811101000000123456",
            "JO71CBJO0000000000001234567890",
            "KZ563190000012344567",
            "XK051212012345678906",
            "KW81CBKU0000000000001234560101",
            "LV97HABA0012345678910",
            "LB92000700000000123123456123",
            "LI7408806123456789012",
            "LT601010012345678901",
            "LU120010001234567891",
            "MT31MALT01100000000000000000123",
            "MR1300020001010000123456753",
            "MU43BOMM0101123456789101000MUR",
            "MD21EX000000000001234567",
            "MC5810096180790123456789085",
            "ME25505000012345678951",
            "NL02ABNA0123456789",
            "MK07200002785123453",
            "NO8330001234567",
            "PK36SCBL0000001123456702",
            "PS92PALS000000000400123456702",
            "PL10105000997603123456789123",
            "PT50002700000001234567833",
            "QA54QNBA000000000000693123456",
            "RO09BCYP0000001234567890",
            "LC14BOSL123456789012345678901234",
            "SM76P0854009812123456789123",
            "ST23000200000289355710148",
            "SA4420000001234567891234",
            "RS35105008123123123173",
            "SC52BAHL01031234567890123456USD",
            "SK8975000000000012345671",
            "SI56192001234567892",
            "ES7921000813610123456789",
            "SE7280000810340009783242",
            "CH5604835012345678009",
            "TL380010012345678910106",
            "TN5904018104004942712345",
            "TR320010009999901234567890",
            "UA903052992990004149123456789",
            "AE460090000000123456789",
            "GB33BUKB20201555555555",
            "VG21PACG0000000123456789"
        ]
        for iban in ibans:
            with self.subTest(iban=iban):
                parse_ibans = sf.parseIBANNumbers(iban)
                self.assertIsInstance(parse_ibans, list)
                self.assertIn(iban, parse_ibans)

        # Invalid IBANs
        ibans = [
            # Invalid country code
            "ZZ21PACG0000000123456789",
            # Invalid length for country code
            "VG123456789012345",
            # Invalid mod 97 remainder
            "VG21PACG0000000123456111"
        ]
        for iban in ibans:
            with self.subTest(iban=iban):
                parse_ibans = sf.parseIBANNumbers(iban)
                self.assertIsInstance(parse_ibans, list)
                self.assertNotIn(iban, parse_ibans)

    def test_parse_emails_should_return_list_of_emails_from_string(self):
        """
        Test parseEmails(self, data)
        """
        sf = SpiderFoot(self.default_options)

        parse_emails = sf.parseEmails("<html><body><p>From:noreply@spiderfoot.net</p><p>Subject:Hello user@spiderfoot.net, here's some text</p></body></html>")
        self.assertIsInstance(parse_emails, list)
        self.assertIn('noreply@spiderfoot.net', parse_emails)
        self.assertIn('user@spiderfoot.net', parse_emails)

    def test_parse_emails_invalid_data_should_return_list(self):
        """
        Test parseEmails(self, data)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                emails = sf.parseEmails(invalid_type)
                self.assertIsInstance(emails, list)

    @unittest.skip("todo")
    def test_ssl_der_to_pem(self):
        """
        Test sslDerToPem(self, der)
        """
        sf = SpiderFoot(self.default_options)
        pem = sf.sslDerToPem(None)

        self.assertEqual(pem, None)

        self.assertEqual('TBD', 'TBD')

    def test_ssl_der_to_pem_invalid_cert_should_return_none(self):
        """
        Test sslDerToPem(self, der)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type), self.assertRaises(TypeError):
                sf.sslDerToPem(invalid_type)

    def test_parse_cert_should_return_a_dict(self):
        """
        Test parseCert(self, rawcert, fqdn=None, expiringdays=30)
        """
        sf = SpiderFoot(self.default_options)

        cert = "-----BEGIN CERTIFICATE-----\r\nMIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMTDkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0NlowSjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMTGkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EFq6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWAa6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIGCCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNvbTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9kc3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAwVAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcCARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAzMDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwuY3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsFAAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJouM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwuX4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlGPfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==\r\n-----END CERTIFICATE-----"

        parse_cert = sf.parseCert(cert)
        self.assertIsInstance(parse_cert, dict)

        parse_cert = sf.parseCert(cert, 'spiderfoot.net')
        self.assertIsInstance(parse_cert, dict)

    def test_parse_cert_invalid_cert_should_return_none(self):
        """
        Test parseCert(self, rawcert, fqdn=None, expiringdays=30)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                parse_cert = sf.parseCert(invalid_type, 'spiderfoot.net', 30)
                self.assertEqual(None, parse_cert)

    def test_parse_cert_invalid_fqdn_should_return_none(self):
        """
        Test parseCert(self, rawcert, fqdn=None, expiringdays=30)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                parse_cert = sf.parseCert(None, invalid_type, 30)
                self.assertEqual(None, parse_cert)

    def test_parse_cert_invalid_expiringdays_should_return_none(self):
        """
        Test parseCert(self, rawcert, fqdn=None, expiringdays=30)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                parse_cert = sf.parseCert(None, 'spiderfoot.net', invalid_type)
                self.assertEqual(None, parse_cert)

    def test_extract_urls_should_extract_urls_from_string(self):
        """
        Test extractUrls(self, content)
        """
        sf = SpiderFoot(self.default_options)

        urls = sf.extractUrls("abchttps://example.spiderfoot.net/path\rabchttp://example.spiderfoot.net:1337/path\rabc")
        self.assertIsInstance(urls, list)
        self.assertIn("https://example.spiderfoot.net/path", urls)
        self.assertIn("http://example.spiderfoot.net:1337/path", urls)

    def test_parse_links_should_return_a_dict_of_urls_from_string(self):
        """
        Test parseLinks(self, url, data, domains)
        """
        sf = SpiderFoot(self.default_options)

        parse_links = sf.parseLinks('url', 'example html content', 'domains')
        self.assertIsInstance(parse_links, dict)

        parse_links = sf.parseLinks('http://spiderfoot.net/', 'example html content<a href="http://spiderfoot.net/path"></a>', 'domains')
        self.assertIsInstance(parse_links, dict)

        self.assertEqual('TBD', 'TBD')

    def test_parse_links_invalid_url_should_return_a_dict(self):
        """
        Test parseLinks(self, url, data, domains)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                parse_links = sf.parseLinks(invalid_type, 'example html content', 'domains')
                self.assertIsInstance(parse_links, dict)

    def test_parse_links_invalid_data_should_return_a_dict(self):
        """
        Test parseLinks(self, url, data, domains)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                parse_links = sf.parseLinks("", invalid_type, 'domains')
                self.assertIsInstance(parse_links, dict)

    def test_parse_links_invalid_domains_should_return_a_dict(self):
        """
        Test parseLinks(self, url, data, domains)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                parse_links = sf.parseLinks('url', 'example html content', invalid_type)
                self.assertIsInstance(parse_links, dict)

    def test_url_encode_unicode_should_return_a_string(self):
        """
        Test urlEncodeUnicode(self, url)
        """
        sf = SpiderFoot(self.default_options)

        url_encode_unicode = sf.urlEncodeUnicode('url')
        self.assertIsInstance(url_encode_unicode, str)

    def test_get_session_should_return_a_session(self):
        """
        Test getSession(self)
        """
        sf = SpiderFoot(self.default_options)
        session = sf.getSession()
        self.assertIn("requests.sessions.Session", str(session))

    def test_remove_url_creds_should_remove_credentials_from_url(self):
        """
        Test removeUrlCreds(self, url):
        """
        url = "http://local/?key=secret&pass=secret&user=secret&password=secret"

        sf = SpiderFoot(self.default_options)
        new_url = sf.removeUrlCreds(url)
        self.assertNotIn("secret", new_url)

    def test_isValidLocalOrLoopbackIp_argument_ip_should_return_a_bool(self):
        """
        Test isValidLocalOrLoopbackIp(self, ip: str) -> bool:
        """
        sf = SpiderFoot(self.default_options)

        self.assertTrue(sf.isValidLocalOrLoopbackIp('127.0.0.1'))
        self.assertTrue(sf.isValidLocalOrLoopbackIp('127.0.0.2'))
        self.assertTrue(sf.isValidLocalOrLoopbackIp('::1'))

        self.assertTrue(sf.isValidLocalOrLoopbackIp('10.1.1.1'))
        self.assertTrue(sf.isValidLocalOrLoopbackIp('fdd1:a677:c70c:b8c5:1234:1234:1234:1234'))

        self.assertFalse(sf.isValidLocalOrLoopbackIp('1.1.1.1'))
        self.assertFalse(sf.isValidLocalOrLoopbackIp('2606:4700:4700::1111'))

        self.assertFalse(sf.isValidLocalOrLoopbackIp('invalid ip address'))

    def test_useProxyForUrl_argument_url_should_return_a_bool(self):
        """
        Test useProxyForUrl(self, url)
        """
        opts = self.default_options

        proxy_host = 'spiderfoot.net'

        opts['_socks1type'] = '5'
        opts['_socks2addr'] = proxy_host
        opts['_socks3port'] = '8080'

        sf = SpiderFoot(opts)
        self.assertFalse(sf.useProxyForUrl('10.1.1.1'))
        self.assertFalse(sf.useProxyForUrl('172.16.1.1'))
        self.assertFalse(sf.useProxyForUrl('192.168.1.1'))
        self.assertFalse(sf.useProxyForUrl('127.0.0.1'))
        self.assertFalse(sf.useProxyForUrl('localhost'))
        self.assertFalse(sf.useProxyForUrl('test.local'))
        self.assertFalse(sf.useProxyForUrl(proxy_host))

    def test_fetchUrl_argument_url_should_return_http_response_as_dict(self):
        """
        Test fetchUrl(self, url, fatal=False, cookies=None, timeout=30,
                 useragent="SpiderFoot", headers=None, noLog=False,
                 postData=None, disableContentEncoding=False, sizeLimit=None,
                 headOnly=False, verify=False)
        """
        sf = SpiderFoot(self.default_options)

        res = sf.fetchUrl("https://spiderfoot.net/")
        self.assertIsInstance(res, dict)
        self.assertEqual(res['code'], "200")
        self.assertNotEqual(res['content'], None)

    def test_fetchUrl_argument_headOnly_should_return_http_response_as_dict(self):
        """
        Test fetchUrl(self, url, fatal=False, cookies=None, timeout=30,
                 useragent="SpiderFoot", headers=None, noLog=False,
                 postData=None, disableContentEncoding=False, sizeLimit=None,
                 headOnly=False, verify=False)
        """
        sf = SpiderFoot(self.default_options)

        res = sf.fetchUrl("https://spiderfoot.net/", headOnly=True)
        self.assertIsInstance(res, dict)
        self.assertEqual(res['code'], "301")
        self.assertEqual(res['content'], None)

    def test_fetchUrl_argument_url_invalid_type_should_return_none(self):
        """
        Test fetchUrl(self, url, fatal=False, cookies=None, timeout=30,
                 useragent="SpiderFoot", headers=None, noLog=False,
                 postData=None, disableContentEncoding=False, sizeLimit=None,
                 headOnly=False, verify=False)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                res = sf.fetchUrl(invalid_type)
                self.assertEqual(None, res)

    def test_fetchUrl_argument_url_invalid_url_should_return_None(self):
        """
        Test fetchUrl(self, url, fatal=False, cookies=None, timeout=30,
                 useragent="SpiderFoot", headers=None, noLog=False,
                 postData=None, disableContentEncoding=False, sizeLimit=None,
                 headOnly=False, verify=False)
        """
        sf = SpiderFoot(self.default_options)

        res = sf.fetchUrl("")
        self.assertEqual(None, res)

        res = sf.fetchUrl("://spiderfoot.net/")
        self.assertEqual(None, res)

        res = sf.fetchUrl("file:///etc/hosts")
        self.assertEqual(None, res)

        res = sf.fetchUrl("irc://spiderfoot.net:6697/")
        self.assertEqual(None, res)

    def test_check_dns_wildcard_invalid_target_should_return_none(self):
        """
        Test checkDnsWildcard(self, target)
        """
        sf = SpiderFoot(self.default_options)

        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                check_dns_wildcard = sf.checkDnsWildcard(invalid_type)
                self.assertIsInstance(check_dns_wildcard, bool)

    def test_check_dns_wildcard_should_return_a_boolean(self):
        """
        Test checkDnsWildcard(self, target)
        """
        sf = SpiderFoot(self.default_options)

        check_dns_wildcard = sf.checkDnsWildcard('local')
        self.assertIsInstance(check_dns_wildcard, bool)

    @unittest.skip("todo")
    def test_google_iterate(self):
        """
        Test googleIterate(self, searchString, opts=dict())
        """
        sf = SpiderFoot(self.default_options)

        sf.googleIterate(None, None)
        self.assertEqual('TBD', 'TBD')

    @unittest.skip("todo")
    def test_bing_iterate(self):
        """
        Test bingIterate(self, searchString, opts=dict())
        """
        sf = SpiderFoot(self.default_options)

        sf.bingIterate(None, None)
        self.assertEqual('TBD', 'TBD')
