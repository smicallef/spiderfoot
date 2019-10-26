# test_spiderfoot.py
from sflib import SpiderFoot
import unittest

class TestSpiderFoot(unittest.TestCase):
    """
    Test SpiderFoot
    """

    default_config = dict()

    def test_init(self):
        """
        Test __init__(self, options, handle=None):
        """
        sf = SpiderFoot(None)
        self.assertEqual('TBD', 'TBD')

    def test_update_socket(self):
        """
        Test updateSocket(self, sock)
        """
        sf = SpiderFoot(dict())

        sf.updateSocket(None)
        self.assertEqual('TBD', 'TBD')

    def test_revert_socket(self):
        """
        Test revertSocket(self)
        """
        sf = SpiderFoot(dict())

        sf.revertSocket()
        self.assertEqual('TBD', 'TBD')

    def test_refresh_tor_ident(self):
        """
        Test refreshTorIdent(self)
        """
        sf = SpiderFoot(dict())

        sf.refreshTorIdent()
        self.assertEqual('TBD', 'TBD')

    def test_opt_value_to_data(self):
        """
        Test optValueToData(self, val, fatal=True, splitLines=True)
        """
        sf = SpiderFoot(dict())

        sf.optValueToData(None)
        self.assertEqual('TBD', 'TBD')

    def test_build_graph_data(self):
        """
        Test buildGraphData(self, data, flt=list())
        """
        sf = SpiderFoot(dict())

        sf.buildGraphData(None)
        self.assertEqual('TBD', 'TBD')

    def test_build_graph_gexf(self):
        """
        Test buildGraphGexf(self, root, title, data, flt=[])
        """
        sf = SpiderFoot(dict())

        sf.buildGraphGexf(None, None, None)
        self.assertEqual('TBD', 'TBD')

    def test_build_graph_json(self):
        """
        Test buildGraphJson(self, root, data, flt=list())
        """
        sf = SpiderFoot(dict())

        sf.buildGraphJson(None, None)
        self.assertEqual('TBD', 'TBD')

    def test_set_dbh(self):
        """
        Test setDbh(self, handle)
        """
        self.assertEqual('TBD', 'TBD')

    def test_set_guid(self):
        """
        Test setGUID(self, uid)
        """
        self.assertEqual('TBD', 'TBD')

    def test_gen_scan_instance_guid_should_return_a_string(self):
        """
        Test genScanInstanceGUID(self, scanName)
        """
        sf = SpiderFoot(dict())

        scan_instance_id = sf.genScanInstanceGUID(None)
        self.assertEqual(str, type(scan_instance_id))

    def test_dblog(self):
        """
        Test _dblog(self, level, message, component=None)
        """
        self.assertEqual('TBD', 'TBD')

    def test_error(self):
        """
        Test error(self, error, exception=True)
        """
        sf = SpiderFoot(dict())

        sf.error(None)
        self.assertEqual('TBD', 'TBD')

    def test_fatal(self):
        """
        Test fatal(self, error)
        """
        sf = SpiderFoot(dict())

        sf.fatal(None)
        self.assertEqual('TBD', 'TBD')

    def test_status(self):
        """
        Test status(self, message)
        """
        sf = SpiderFoot(dict())

        sf.status(None)
        self.assertEqual('TBD', 'TBD')

    def test_info(self):
        """
        Test info(self, message)
        """
        sf = SpiderFoot(dict())

        sf.info(None)
        self.assertEqual('TBD', 'TBD')

    def test_debug(self):
        """
        Test debug(self, message)
        """
        sf = SpiderFoot(dict())

        sf.debug(None)
        self.assertEqual('TBD', 'TBD')

    def test_my_path_should_return_a_unicode(self):
        """
        Test myPath(self)
        """
        sf = SpiderFoot(dict())

        path = sf.myPath()
        self.assertEqual(unicode, type(path))

    def test_hash_string_should_return_a_string(self):
        """
        Test hashstring(self, string)
        """
        sf = SpiderFoot(dict())

        hash_string = sf.hashstring('example string')
        self.assertEqual(str, type(hash_string))

    def test_cache_path_should_return_a_unicode(self):
        """
        Test cachePath(self)
        """
        sf = SpiderFoot(dict())

        cache_path = sf.cachePath()
        self.assertEqual(unicode, type(cache_path))

    def test_cache_put(self):
        """
        Test cachePut(self, label, data)
        """
        self.assertEqual('TBD', 'TBD')

    def test_cache_get(self):
        """
        Test cacheGet(self, label, timeoutHrs)
        """
        self.assertEqual('TBD', 'TBD')

    def test_cache_get_invalid_label(self):
        """
        Test cacheGet(self, label, timeoutHrs)
        """
        sf = SpiderFoot(dict())

        cache_get = sf.cacheGet(None, None)
        self.assertEqual('TBD', 'TBD')

    def test_cache_get_invalid_timeout(self):
        """
        Test cacheGet(self, label, timeoutHrs)
        """
        sf = SpiderFoot(dict())

        cache_get = sf.cacheGet('', None)
        self.assertEqual('TBD', 'TBD')

    def test_config_serialize(self):
        """
        Test configSerialize(self, opts, filterSystem=True)
        """
        self.assertEqual('TBD', 'TBD')

    def test_config_unserialize(self):
        """
        Test configUnserialize(self, opts, referencePoint, filterSystem=True)
        """
        self.assertEqual('TBD', 'TBD')

    def test_target_type(self):
        """
        Test targetType(self, target)
        """
        self.assertEqual('TBD', 'TBD')

    def test_modules_producing(self):
        """
        Test modulesProducing(self, events)
        """
        self.assertEqual('TBD', 'TBD')

    def test_modules_consuming(self):
        """
        Test modulesConsuming(self, events)
        """
        self.assertEqual('TBD', 'TBD')

    def test_events_from_modules(self):
        """
        Test eventsFromModules(self, modules)
        """
        self.assertEqual('TBD', 'TBD')

    def test_events_to_modules(self):
        """
        Test eventsToModules(self, modules)
        """
        self.assertEqual('TBD', 'TBD')

    def test_url_relative_to_absolute_should_return_a_string(self):
        """
        Test urlRelativeToAbsolute(self, url)
        """
        sf = SpiderFoot(dict())

        relative_url = sf.urlRelativeToAbsolute(None)
        self.assertEqual(str, type(relative_url))

    def test_url_base_dir_should_return_a_string(self):
        """
        Test urlBaseDir(self, url)
        """
        sf = SpiderFoot(dict())

        base_dir = sf.urlBaseDir(None)
        self.assertEqual(str, type(base_dir))

    def test_url_base_url_should_return_a_string(self):
        """
        Test urlBaseUrl(self, url)
        """
        sf = SpiderFoot(dict())

        base_url = sf.urlBaseUrl(None)
        self.assertEqual(str, type(base_url))

    def test_url_fqdn_should_return_a_string(self):
        """
        Test urlFQDN(self, url)
        """
        sf = SpiderFoot(dict())

        fqdn = sf.urlFQDN(None)
        self.assertEqual(str, type(fqdn))

    def test_domain_keyword(self):
        """
        Test domainKeyword(self, domain, tldList)
        """
        self.assertEqual('TBD', 'TBD')

    def test_domain_keywords(self):
        """
        Test domainKeywords(self, domainList, tldList)
        """
        self.assertEqual('TBD', 'TBD')

    def test_host_domain(self):
        """
        Test hostDomain(self, hostname, tldList)
        """
        self.assertEqual('TBD', 'TBD')

    def test_is_domain(self):
        """
        Test isDomain(self, hostname, tldList)
        """
        self.assertEqual('TBD', 'TBD')

    def test_valid_ip(self):
        """
        Test validIP(self, address)
        """
        self.assertEqual('TBD', 'TBD')

    def test_valid_ip6(self):
        """
        Test validIP6(self, address)
        """
        self.assertEqual('TBD', 'TBD')

    def test_valid_ip_network(self):
        """
        Test validIpNetwork(self, cidr)
        """
        self.assertEqual('TBD', 'TBD')

    def tes_normalize_dns(self):
        """
        Test normalizeDNS(self, res)
        """
        self.assertEqual('TBD', 'TBD')

    def test_sanitise_input(self):
        """
        Test sanitiseInput(self, cmd)
        """
        self.assertEqual('TBD', 'TBD')

    def test_dictwords_should_return_a_list(self):
        """
        Test dictwords(self)
        """
        sf = SpiderFoot(dict())

        dict_words = sf.dictwords()
        self.assertEqual(list, type(dict_words))

    def test_dictnames_should_return_a_list(self):
        """
        Test dictnames(self)
        """
        sf = SpiderFoot(dict())

        dict_names = sf.dictnames()
        self.assertEqual(list, type(dict_names))

    def test_data_parent_child_to_tree(self):
        """
        Test dataParentChildToTree(self, data)
        """
        self.assertEqual('TBD', 'TBD')

    def test_resolve_host(self):
        """
        Test resolveHost(self, host)
        """
        self.assertEqual('TBD', 'TBD')

    def test_resolve_ip(self):
        """
        Test resolveIP(self, ipaddr)
        """
        self.assertEqual('TBD', 'TBD')

    def test_resolve_host6(self):
        """
        Test resolveHost6(self, hostname)
        """
        self.assertEqual('TBD', 'TBD')

    def test_validate_ip(self):
        """
        Test validateIP(self, host, ip)
        """
        self.assertEqual('TBD', 'TBD')

    def test_resolve_targets(self):
        """
        Test resolveTargets(self, target, validateReverse)
        """
        self.assertEqual('TBD', 'TBD')

    def test_safe_socket(self):
        """
        Test safeSocket(self, host, port, timeout)
        """
        self.assertEqual('TBD', 'TBD')

    def test_safe_ssl_socket(self):
        """
        Test safeSSLSocket(self, host, port, timeout)
        """
        self.assertEqual('TBD', 'TBD')

    def test_parse_robots_txt(self):
        """
        Test parseRobotsTxt(self, robotsTxtData)
        """
        self.assertEqual('TBD', 'TBD')

    def test_parse_emails(self):
        """
        Test parseEmails(self, data)
        """
        self.assertEqual('TBD', 'TBD')

    def test_ssl_der_to_pem(self):
        """
        Test sslDerToPem(self, der)
        """
        self.assertEqual('TBD', 'TBD')

    def test_parse_cert(self):
        """
        Test parseCert(self, rawcert, fqdn=None, expiringdays=30)
        """
        self.assertEqual('TBD', 'TBD')

    def test_parse_links(self):
        """
        Test parseLinks(self, url, data, domains, parseText=True)
        """
        self.assertEqual('TBD', 'TBD')

    def test_url_encode_unicode(self):
        """
        Test urlEncodeUnicode(self, url)
        """
        self.assertEqual('TBD', 'TBD')

    def test_fetch_url(self):
        """
        Test fetchUrl(self, url, fatal=False, cookies=None, timeout=30,
                 useragent="SpiderFoot", headers=None, noLog=False,
                 postData=None, dontMangle=False, sizeLimit=None,
                 headOnly=False, verify=False)
        """
        sf = SpiderFoot(dict())

        sf.fetchUrl(None)
        self.assertEqual('TBD', 'TBD')

    def test_check_dns_wildcard_should_return_a_boolean(self):
        """
        Test checkDnsWildcard(self, target)
        """
        sf = SpiderFoot(dict())

        check_dns_wildcard = sf.checkDnsWildcard(None)
        self.assertEqual(bool, type(check_dns_wildcard))

    def test_google_iterate(self):
        """
        Test googleIterate(self, searchString, opts=dict())
        """
        self.assertEqual('TBD', 'TBD')

    def test_bing_iterate(self):
        """
        Test bingIterate(self, searchString, opts=dict())
        """
        self.assertEqual('TBD', 'TBD')

if __name__ == '__main__':
    unittest.main()

