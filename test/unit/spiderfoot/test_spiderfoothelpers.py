# test_spiderfoot.py
import pytest
import unittest

from spiderfoot import SpiderFootHelpers


@pytest.mark.usefixtures
class TestSpiderFootHelpers(unittest.TestCase):

    def test_data_path_should_return_a_string(self):
        data_path = SpiderFootHelpers.dataPath()
        self.assertIsInstance(data_path, str)

    def test_cache_path_should_return_a_string(self):
        cache_path = SpiderFootHelpers.cachePath()
        self.assertIsInstance(cache_path, str)

    def test_log_path_should_return_a_string(self):
        log_path = SpiderFootHelpers.logPath()
        self.assertIsInstance(log_path, str)

    def test_target_type(self):
        target_type = SpiderFootHelpers.targetTypeFromString("0.0.0.0")
        self.assertEqual('IP_ADDRESS', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("noreply@spiderfoot.net")
        self.assertEqual('EMAILADDR', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("0.0.0.0/0")
        self.assertEqual('NETBLOCK_OWNER', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("+1234567890")
        self.assertEqual('PHONE_NUMBER', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString('"Human Name"')
        self.assertEqual('HUMAN_NAME', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString('"abc123"')
        self.assertEqual('USERNAME', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("1234567890")
        self.assertEqual('BGP_AS_OWNER', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("::1")
        self.assertEqual('IPV6_ADDRESS', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("spiderfoot.net")
        self.assertEqual('INTERNET_NAME', target_type)
        target_type = SpiderFootHelpers.targetTypeFromString("1HesYJSP1QqcyPEjnQ9vzBL1wujruNGe7R")
        self.assertEqual('BITCOIN_ADDRESS', target_type)

    def test_target_type_invalid_seed_should_return_none(self):
        target_type = SpiderFootHelpers.targetTypeFromString(None)
        self.assertEqual(None, target_type)

        target_type = SpiderFootHelpers.targetTypeFromString("")
        self.assertEqual(None, target_type)

        target_type = SpiderFootHelpers.targetTypeFromString('""')
        self.assertEqual(None, target_type)

    def test_urlRelativeToAbsolute_argument_url_relative_path_should_return_an_absolute_path(self):
        relative_url = SpiderFootHelpers.urlRelativeToAbsolute('/somewhere/else/../../path?param=value#fragment')
        self.assertIsInstance(relative_url, str)
        self.assertEqual('/path?param=value#fragment', relative_url)

    def test_url_base_dir_should_return_a_string(self):
        base_dir = SpiderFootHelpers.urlBaseDir('http://localhost.local/path?param=value#fragment')
        self.assertIsInstance(base_dir, str)
        self.assertEqual('http://localhost.local/', base_dir)

    def test_url_base_url_should_return_a_string(self):
        base_url = SpiderFootHelpers.urlBaseUrl('http://localhost.local/path?param=value#fragment')
        self.assertIsInstance(base_url, str)
        self.assertEqual('http://localhost.local', base_url)

    def test_dictionaryWordsFromWordlists_should_return_a_set(self):
        words = SpiderFootHelpers.dictionaryWordsFromWordlists()
        self.assertIsInstance(words, set)
        self.assertTrue(len(words))

    def test_dictionaryWordsFromWordlists_argument_wordlists_missing_wordlist_should_raise_IOError(self):
        with self.assertRaises(IOError):
            SpiderFootHelpers.dictionaryWordsFromWordlists(['does not exist'])

    def test_humanNamesFromWordlists_should_return_a_set(self):
        names = SpiderFootHelpers.humanNamesFromWordlists()
        self.assertIsInstance(names, set)
        self.assertTrue(len(names))

    def test_humanNamesFromWordlists_argument_wordlists_missing_wordlist_should_raise_IOError(self):
        with self.assertRaises(IOError):
            SpiderFootHelpers.humanNamesFromWordlists(['does not exist'])

    def test_usernamesFromWordlists_should_return_a_set(self):
        users = SpiderFootHelpers.usernamesFromWordlists()
        self.assertIsInstance(users, set)
        self.assertTrue(len(users))

    def test_usernamesFromWordlists_argument_wordlists_missing_wordlist_should_raise_IOError(self):
        with self.assertRaises(IOError):
            SpiderFootHelpers.usernamesFromWordlists(['does not exist'])

    def test_buildGraphData_invalid_data_type_should_raise_TypeError(self):
        invalid_types = [None, "", bytes(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootHelpers.buildGraphData(invalid_type)

    def test_buildGraphData_empty_data_should_raise_ValueError(self):
        with self.assertRaises(ValueError):
            SpiderFootHelpers.buildGraphData([])

    def test_buildGraphData_data_row_with_invalid_number_of_columns_should_raise_ValueError(self):
        with self.assertRaises(ValueError):
            SpiderFootHelpers.buildGraphData(
                [
                    ['only one column']
                ]
            )

    def test_buildGraphData_should_return_a_set(self):
        graph_data = SpiderFootHelpers.buildGraphData(
            [
                ["test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test"]
            ]
        )
        self.assertIsInstance(graph_data, set)

        self.assertEqual('TBD', 'TBD')

    def test_buildGraphGexf_should_return_bytes(self):
        gexf = SpiderFootHelpers.buildGraphGexf('test root', 'test title', [["test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "ENTITY", "test", "test", "test"]])
        self.assertIsInstance(gexf, bytes)

        self.assertEqual('TBD', 'TBD')

    def test_buildGraphJson_should_return_a_string(self):
        json = SpiderFootHelpers.buildGraphJson('test root', [["test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "test", "ENTITY", "test", "test", "test"]])
        self.assertIsInstance(json, str)

        self.assertEqual('TBD', 'TBD')

    def test_dataParentChildToTree_invalid_data_type_should_return_TypeError(self):
        invalid_types = [None, "", bytes(), list(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootHelpers.dataParentChildToTree(invalid_type)

    def test_dataParentChildToTree_empty_data_should_return_ValueError(self):
        with self.assertRaises(ValueError):
            SpiderFootHelpers.dataParentChildToTree(dict())

    def test_dataParentChildToTree_should_return_dict(self):
        tree = SpiderFootHelpers.dataParentChildToTree({"test": {"123": "456"}})
        self.assertIsInstance(tree, dict)

    def test_genScanInstanceId_should_return_a_string(self):
        scan_instance_id = SpiderFootHelpers.genScanInstanceId()
        self.assertIsInstance(scan_instance_id, str)

    def test_extractLinksFromHtml_argument_data_not_containing_links_should_return_an_empty_dict(self):
        parse_links = SpiderFootHelpers.extractLinksFromHtml('url', '<html>example html content</html>', 'domains')
        self.assertIsInstance(parse_links, dict)
        self.assertFalse(parse_links)

    def test_extractLinksFromHtml_argument_data_containing_malformed_html_with_links_should_return_a_dict_of_urls(self):
        url = 'http://spiderfoot.net/'
        parse_links = SpiderFootHelpers.extractLinksFromHtml(
            url,
            '<!DOCTYPE html><html lang="en-US"><meta charset="UTF-8" /><link rel="pingback" href="http://spiderfoot.net/xmlrpc.php">example html content<unclosed tag><a href="http://spiderfoot.net/path"></a><a href="/relative-path"></a></html>',
            'domains'
        )
        self.assertIsInstance(parse_links, dict)

        self.assertEqual(
            parse_links,
            {
                'http://spiderfoot.net/xmlrpc.php': {'source': url, 'original': 'http://spiderfoot.net/xmlrpc.php'},
                'http://spiderfoot.net/path': {'source': url, 'original': 'http://spiderfoot.net/path'},
                'http://spiderfoot.net/relative-path': {'source': url, 'original': '/relative-path'},
            }
        )

    def test_extractLinksFromHtml_invalid_url_should_raise_TypeError(self):
        invalid_types = [None,  bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootHelpers.extractLinksFromHtml(invalid_type, 'example html content', 'domains')

    def test_extractLinksFromHtml_invalid_data_should_raise_TypeError(self):
        invalid_types = [None, bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                with self.assertRaises(TypeError):
                    SpiderFootHelpers.extractLinksFromHtml("", invalid_type, 'domains')

    def test_extractLinksFromHtml_invalid_domains_should_return_a_dict(self):
        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                parse_links = SpiderFootHelpers.extractLinksFromHtml('url', 'example html content', invalid_type)
                self.assertIsInstance(parse_links, dict)

    def test_extractHashesFromText_should_return_a_list(self):
        invalid_types = [None, list(), bytes(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                hashes = SpiderFootHelpers.extractHashesFromText(invalid_type)
                self.assertIsInstance(hashes, list)

    def test_extractHashesFromText_argument_data_should_return_hahes(self):
        md5_hash = "e17cff4eb3e8fbe6ca3b83fb47532dba"
        sha1_hash = "f81efbe70f8116fcf3dc4e9b37725dcb949719f5"
        sha256_hash = "7cd444af3d8de9e195b1f1cb55e7b7d9409dcd4648247c853a2f64b7578dc9b7"
        sha512_hash = "a55a2fe120d7d7d6e2ba930e6c56faa30b9d24a3178a0aff1d89312a89d61d8a9d5b7743e3af6b1a318d99974a1145ed76f85aa8c6574074dfb347613ccd3249"

        hashes = SpiderFootHelpers.extractHashesFromText(f"spiderfoot{md5_hash}spiderfoot{sha1_hash}spiderfoot{sha256_hash}spiderfoot{sha512_hash}spiderfoot")

        self.assertIsInstance(hashes, list)
        self.assertIn(("MD5", md5_hash), hashes)
        self.assertIn(("SHA1", sha1_hash), hashes)
        self.assertIn(("SHA256", sha256_hash), hashes)
        self.assertIn(("SHA512", sha512_hash), hashes)

    def test_valid_email_should_return_a_boolean(self):
        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                valid_email = SpiderFootHelpers.validEmail(invalid_type)
                self.assertIsInstance(valid_email, bool)
                self.assertFalse(valid_email)

        valid_email = SpiderFootHelpers.validEmail('%@localhost.local')
        self.assertIsInstance(valid_email, bool)
        self.assertFalse(valid_email)

        valid_email = SpiderFootHelpers.validEmail('...@localhost.local')
        self.assertIsInstance(valid_email, bool)
        self.assertFalse(valid_email)

        valid_email = SpiderFootHelpers.validEmail('root@localhost.local\n.com')
        self.assertIsInstance(valid_email, bool)
        self.assertFalse(valid_email)

        valid_email = SpiderFootHelpers.validEmail('root@localhost')
        self.assertIsInstance(valid_email, bool)
        self.assertFalse(valid_email)

        valid_email = SpiderFootHelpers.validEmail('root@localhost.local')
        self.assertIsInstance(valid_email, bool)
        self.assertTrue(valid_email)

    def test_validPhoneNumber_should_return_a_boolean(self):
        invalid_types = [None, "", bytes(), list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                valid_phone = SpiderFootHelpers.validPhoneNumber(invalid_type)
                self.assertIsInstance(valid_phone, bool)
                self.assertFalse(valid_phone)

        valid_phone = SpiderFootHelpers.validPhoneNumber('+1234567890')
        self.assertIsInstance(valid_phone, bool)
        self.assertFalse(valid_phone)

        valid_phone = SpiderFootHelpers.validPhoneNumber('+12345678901234567890')
        self.assertIsInstance(valid_phone, bool)
        self.assertFalse(valid_phone)

        valid_phone = SpiderFootHelpers.validPhoneNumber('+12345678901')
        self.assertIsInstance(valid_phone, bool)
        self.assertTrue(valid_phone)

    def test_validLEI_should_return_a_boolean(self):
        invalid_types = [None, "", bytes(), list(), dict(), int()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                valid_phone = SpiderFootHelpers.validLEI(invalid_type)
                self.assertIsInstance(valid_phone, bool)
                self.assertFalse(valid_phone)

        valid_lei = SpiderFootHelpers.validLEI('7ZW8QJWVPR4P1J1KQYZZ')
        self.assertIsInstance(valid_lei, bool)
        self.assertFalse(valid_lei)

        valid_lei = SpiderFootHelpers.validLEI('7ZW8QJWVPR4P1J1KQY45')
        self.assertIsInstance(valid_lei, bool)
        self.assertTrue(valid_lei)

    def test_countryCodes_should_return_a_dict(self):
        country_code_dict = SpiderFootHelpers.countryCodes()
        self.assertIsInstance(country_code_dict, dict)

    def test_countryNameFromCountryCode_argument_countryCode_should_return_country_as_a_string(self):
        country_name = SpiderFootHelpers.countryNameFromCountryCode('US')
        self.assertIsInstance(country_name, str)
        self.assertEqual(country_name, "United States")

    def test_countryNameFromTld_argument_tld_should_return_country_as_a_string(self):
        tlds = ['com', 'net', 'org', 'gov', 'mil']
        for tld in tlds:
            with self.subTest(tld=tld):
                country_name = SpiderFootHelpers.countryNameFromTld(tld)
                self.assertIsInstance(country_name, str)
                self.assertEqual(country_name, "United States")

    def test_extractEmailsFromText_should_return_list_of_emails_from_string(self):
        emails = SpiderFootHelpers.extractEmailsFromText("<html><body><p>From:noreply@spiderfoot.net</p><p>Subject:Hello user@spiderfoot.net, here's some text</p></body></html>")
        self.assertIsInstance(emails, list)
        self.assertIn('noreply@spiderfoot.net', emails)
        self.assertIn('user@spiderfoot.net', emails)

    def test_extractEmailsFromText_invalid_data_should_return_list(self):
        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                emails = SpiderFootHelpers.extractEmailsFromText(invalid_type)
                self.assertIsInstance(emails, list)

    def test_extractPgpKeysFromText_should_return_list_of_pgp_keys_from_string(self):
        key1 = "-----BEGIN PGP PUBLIC KEY BLOCK-----Version: software v1.2.3\nComment: sample comment\n\nmQINBFRUAGoBEACuk6ze2V2pZtScf1Ul25N2CX19AeL7sVYwnyrTYuWdG2FmJx4x\nDLTLVUazp2AEm/JhskulL/7VCZPyg7ynf+o20Tu9/6zUD7p0rnQA2k3Dz+7dKHHh\neEsIl5EZyFy1XodhUnEIjel2nGe6f1OO7Dr3UIEQw5JnkZyqMcbLCu9sM2twFyfa\na8JNghfjltLJs3/UjJ8ZnGGByMmWxrWQUItMpQjGr99nZf4L+IPxy2i8O8WQewB5\nfvfidBGruUYC+mTw7CusaCOQbBuZBiYduFgH8hRW97KLmHn0xzB1FV++KI7syo8q\nXGo8Un24WP40IT78XjKO\n=nUop\n-----END PGP PUBLIC KEY BLOCK-----"
        key2 = "-----BEGIN PGP PRIVATE KEY BLOCK-----Version: software v1.2.3\nComment: sample comment\n\nmQINBFRUAGoBEACuk6ze2V2pZtScf1Ul25N2CX19AeL7sVYwnyrTYuWdG2FmJx4x\nDLTLVUazp2AEm/JhskulL/7VCZPyg7ynf+o20Tu9/6zUD7p0rnQA2k3Dz+7dKHHh\neEsIl5EZyFy1XodhUnEIjel2nGe6f1OO7Dr3UIEQw5JnkZyqMcbLCu9sM2twFyfa\na8JNghfjltLJs3/UjJ8ZnGGByMmWxrWQUItMpQjGr99nZf4L+IPxy2i8O8WQewB5\nfvfidBGruUYC+mTw7CusaCOQbBuZBiYduFgH8hRW97KLmHn0xzB1FV++KI7syo8q\nXGo8Un24WP40IT78XjKO\n=nUop\n-----END PGP PRIVATE KEY BLOCK-----"
        keys = SpiderFootHelpers.extractPgpKeysFromText(f"<html><body><p>sample{key1}sample</p><p>sample{key2}sample</p></body></html>")
        self.assertIsInstance(keys, list)
        self.assertIn(key1, keys)
        self.assertIn(key2, keys)
        self.assertEqual(len(keys), 2)

    def test_extractIbansFromText_should_return_a_list(self):
        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                ibans = SpiderFootHelpers.extractIbansFromText(invalid_type)
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
                extract_ibans = SpiderFootHelpers.extractIbansFromText(iban)
                self.assertIsInstance(extract_ibans, list)
                self.assertIn(iban, extract_ibans)

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
                extract_ibans = SpiderFootHelpers.extractIbansFromText(iban)
                self.assertIsInstance(extract_ibans, list)
                self.assertNotIn(iban, extract_ibans)

    def test_extractCreditCardsFromText_should_return_a_list(self):
        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                cards = SpiderFootHelpers.extractCreditCardsFromText(invalid_type)
                self.assertIsInstance(cards, list)

        cards = SpiderFootHelpers.extractCreditCardsFromText("spiderfoot4111 1111 1111 1111spiderfoot")
        self.assertIsInstance(cards, list)
        self.assertEqual(["4111111111111111"], cards)

    def test_extractUrlsFromText_should_extract_urls_from_string(self):
        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                cards = SpiderFootHelpers.extractUrlsFromText(invalid_type)
                self.assertIsInstance(cards, list)

        urls = SpiderFootHelpers.extractUrlsFromText("abchttps://example.spiderfoot.net/path\rabchttp://example.spiderfoot.net:1337/path\rabc")
        self.assertIsInstance(urls, list)
        self.assertIn("https://example.spiderfoot.net/path", urls)
        self.assertIn("http://example.spiderfoot.net:1337/path", urls)

    def test_extractUrlsFromRobotsTxt_should_return_list(self):
        invalid_types = [None, "", bytes(), list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type):
                robots_txt = SpiderFootHelpers.extractUrlsFromRobotsTxt(invalid_type)
                self.assertIsInstance(robots_txt, list)

        robots_txt = SpiderFootHelpers.extractUrlsFromRobotsTxt("disallow:")
        self.assertIsInstance(robots_txt, list)
        self.assertFalse(robots_txt)

        robots_txt = SpiderFootHelpers.extractUrlsFromRobotsTxt("disallow: /disallowed/path\n")
        self.assertIsInstance(robots_txt, list)
        self.assertIn("/disallowed/path", robots_txt)

    def test_sanitise_input(self):
        safe = SpiderFootHelpers.sanitiseInput("example-string")
        self.assertIsInstance(safe, bool)
        self.assertTrue(safe)

        safe = SpiderFootHelpers.sanitiseInput("example-string\n")
        self.assertIsInstance(safe, bool)
        self.assertFalse(safe)

        safe = SpiderFootHelpers.sanitiseInput("example string")
        self.assertIsInstance(safe, bool)
        self.assertFalse(safe)

        safe = SpiderFootHelpers.sanitiseInput("-example-string")
        self.assertIsInstance(safe, bool)
        self.assertFalse(safe)

        safe = SpiderFootHelpers.sanitiseInput("..example-string")
        self.assertIsInstance(safe, bool)
        self.assertFalse(safe)

        safe = SpiderFootHelpers.sanitiseInput("12")
        self.assertIsInstance(safe, bool)
        self.assertFalse(safe)
