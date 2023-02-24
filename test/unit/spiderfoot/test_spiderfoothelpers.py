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
        invalid_types = [None, bytes(), list(), dict()]
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

    def test_sslDerToPem_should_return_a_certificate_as_a_string(self):
        pem = SpiderFootHelpers.sslDerToPem(
            b"0\x82\x07J0\x82\x062\xa0\x03\x02\x01\x02\x02\x10\x0c\x1f\xcb\x18E\x18\xc7\xe3\x86gA#mks\xf10\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x000O1\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x150\x13\x06\x03U\x04\n\x13\x0cDigiCert Inc1)0\'\x06\x03U\x04\x03\x13 DigiCert TLS RSA SHA256 2020 CA10\x1e\x17\r230113000000Z\x17\r240213235959Z0\x81\x961\x0b0\t\x06\x03U\x04\x06\x13\x02US1\x130\x11\x06\x03U\x04\x08\x13\nCalifornia1\x140\x12\x06\x03U\x04\x07\x13\x0bLos Angeles1B0@\x06\x03U\x04\n\x0c9Internet\xc2\xa0Corporation\xc2\xa0for\xc2\xa0Assigned\xc2\xa0Names\xc2\xa0and\xc2\xa0Numbers1\x180\x16\x06\x03U\x04\x03\x13\x0fwww.example.org0\x82\x01\x220\r\x06\t*\x86H\x86\xf7\r\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x000\x82\x01\n\x02\x82\x01\x01\x00\xc2\x80w\x89Y\xb8Eo\xbaJ\xd9\x11\xfa{\xad\xc7W\xd0z\xfb\xb6\xfa\xdd\x05\xbb\xa2\x81q\xbb\xe1\x7f!\xd2_.\xf0\xd2rNu4\xf8\x8db\xe3J\xdaQ\x90\xd4\x01=\x9c\x0c\xc0q\xf7\xe6/\xb6\xd6\x07g&\xd0\xde\xff\x17\xce\xf0\x85\xfd1\xc1f\xca\x87e\x05G*_\xc0\xab\xb8\x8c\xc3\xbf\xd0\x17\x7fc\xa3\\\xf0F\xfb\x86\xaa\xfbM\xd7*^\x7f\x9a\xe0\x13\x97}\xbe\xfb}5W\r]^\x81\x985\xea\x16B\xa2\xd3\xb0t\xf7Y-\xed8\xe7\xfez\x1b\xb36\xe6~\xae?\x9e\xa6\x16\x83\xdeS\x01N\x81\x00\xae\xbbB\xf5\x1fu)4\xcd\xe9\x84\x808\xae<7\x14\xc0\xf0\'\xce0R\xb9\x8a\xdc_\x22\xa0y\xf8ONI\x04\xe2u|\xaa/*\x1e\x03\xecqL\xa3*a\xfco\xca\x91\x1e\x93Z.x\x08X\xf6\xee\xbb4 ]\x9a\xe6\xaf\xc6\xd7\xf2\xbf\n{\xfa\x8e\x92w\xe3l{\x0c@\x86dJ\x15\xecp\xd7r\x8ec0\xe1\x0b\xefZ0\x97.%\x02\x03\x01\x00\x01\xa3\x82\x03\xd80\x82\x03\xd40\x1f\x06\x03U\x1d#\x04\x180\x16\x80\x14\xb7k\xa2\xea\xa8\xaa\x84\x8cy\xea\xb4\xda\x0f\x98\xb2\xc5\x95v\xb9\xf40\x1d\x06\x03U\x1d\x0e\x04\x16\x04\x14\xb0\x93?\xe8\x17\x82\xfdl\xb2\xb6\x17\x87\xcb\xe3\x80\xfe\x82\x9b\x01\x9e0\x81\x81\x06\x03U\x1d\x11\x04z0x\x82\x0fwww.example.org\x82\x0bexample.net\x82\x0bexample.edu\x82\x0bexample.com\x82\x0bexample.org\x82\x0fwww.example.com\x82\x0fwww.example.edu\x82\x0fwww.example.net0\x0e\x06\x03U\x1d\x0f\x01\x01\xff\x04\x04\x03\x02\x05\xa00\x1d\x06\x03U\x1d%\x04\x160\x14\x06\x08+\x06\x01\x05\x05\x07\x03\x01\x06\x08+\x06\x01\x05\x05\x07\x03\x020\x81\x8f\x06\x03U\x1d\x1f\x04\x81\x870\x81\x840@\xa0>\xa0<\x86:http://crl3.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl0@\xa0>\xa0<\x86:http://crl4.digicert.com/DigiCertTLSRSASHA2562020CA1-4.crl0>\x06\x03U\x1d \x0470503\x06\x06g\x81\x0c\x01\x02\x020)0\'\x06\x08+\x06\x01\x05\x05\x07\x02\x01\x16\x1bhttp://www.digicert.com/CPS0\x7f\x06\x08+\x06\x01\x05\x05\x07\x01\x01\x04s0q0$\x06\x08+\x06\x01\x05\x05\x070\x01\x86\x18http://ocsp.digicert.com0I\x06\x08+\x06\x01\x05\x05\x070\x02\x86=http://cacerts.digicert.com/DigiCertTLSRSASHA2562020CA1-1.crt0\t\x06\x03U\x1d\x13\x04\x020\x000\x82\x01\x7f\x06\n+\x06\x01\x04\x01\xd6y\x02\x04\x02\x04\x82\x01o\x04\x82\x01k\x01i\x00v\x00\xee\xcd\xd0d\xd5\xdb\x1a\xce\xc5\\\xb7\x9d\xb4\xcd\x13\xa22\x87F|\xbc\xec\xde\xc3QHYFq\x1f\xb5\x9b\x00\x00\x01\x85\xabH\x05#\x00\x00\x04\x03\x00G0E\x02!\x00\xaa\xdf\x9f+\xa8\xc5t`:\xb6\xfd\x04Z\xdfkk\x1d\x16`\x15x\xad\xefc\x81\x98*\xd38\xb8\xd9\x05\x02 @a\xd7\x22\xa9>\xf8\x17\xd4\x1a\xde\x13L\x01Rj\xe29U!%.\xfb*\x01u\xf7w\xd3\xdb\xce\xfb\x00w\x00s\xd9\x9e\x89\x1bL\x96x\xa0 }G\x9d\xe6\xb2\xc6\x1c\xd0Q^q\x19*\x8ck\x80\x10z\xc1wr\xb5\x00\x00\x01\x85\xabH\x05\x9f\x00\x00\x04\x03\x00H0F\x02!\x00\xd7d\x94\x14\xaek\x80\xba\x91\xce\xf8\x1c\xaf\xb6sW\x89\xe5\xf9\x9b}\x96Z\x00\xcd\x12\xdf=\xce\xefH\xf0\x02!\x00\x97=\xbc\x12s\x1dk\x13\xe0c\x15\xac\x19\x95X\xcb\x8f\xfdO\xb0\xcd\nA\x07,|p\xd9%D\xcb\xc0\x00v\x00H\xb0\xe3k\xda\xa6G4\x0f\xe5j\x02\xfa\x9d0\xeb\x1cR\x01\xcbV\xdd,\x81\xd9\xbb\xbf\xab9\xd8\x84s\x00\x00\x01\x85\xabH\x05^\x00\x00\x04\x03\x00G0E\x02!\x00\xde[\x84{a\xa3%\x8c\'p\x90\x07\xfdb`Q!2\x05\x15\x90XG\x0c\xcf\xe7\x94OS\x84,!\x02 \x0f\xbc\xf2W\xca\x9e\xda\xdaL\xf0%}\xcf\xed\xfa\x87\xe5y(\xde\xb3\xe1\x0b4h]\x87z[\xe4$\n0\r\x06\t*\x86H\x86\xf7\r\x01\x01\x0b\x05\x00\x03\x82\x01\x01\x00Y\xe4J\xd8\xa9\x82\xba\x9aJ\xf1c\x0cmv&u\xb3<t\xbe\xc5\xf7=\xa7\x91\x92\xf8\xcf\x06-X\x10\xed\xf3\xb8\xd6\xfcl\xff\x13\x962\xcdO\xe9\x87$\x85\x0bt\xa2\xc2\xf6\x0f\xf5\xa7\xd8}v\x8a\xae\xe9\xc9X+n\x00o\xb9\xcd$\xee\xc4B\xc5L\x16\x85\x9d4a9#\xbf\xc6\x8e\x95\xc9\x84\xa9\xb2\xe5A\x0fDx\xd7\x95\xb9\xcf\xd9t\xbfXO\xe7\x16\xff|@0\xc4lN\x22M\xcb\x83g:\x93\xbf+\xc5\xc5\x9c\x1a\xf2C\xa1%;\x84\xf6\xf7Sn\xa8\x85\xae\xde\x14t\x910\x06\r\xf2\x07\xd4\xc4\x08\xbaCd\xc5\xe2?\xda\xac\xc5A\xaf\xa47\xe8Bvt\xf7\x13\xbbJ}6Y\x81\x9b\xc7D\xdf\x89s\xb93B\xe8`\xc2Ma]\x12Z\x10\xf6\xef\xff3\x89\x14P\xe8\xd6\x9f\xc6\xb9\\+5\xdb\xad\xed\xdd6\xb6%\xf2\x95\x8a\xaci?\x9a\xfe\x1a\xf8\x15(m\xea\x18Z\xc2\xd2b\x18\xaf@x\xb5\xfa^\t\x8fS\xf9\xcc\xf8#\xa1\x831#\xf4\xc6"
        )
        self.assertIsInstance(pem, str)
        self.assertTrue(pem.startswith('-----BEGIN CERTIFICATE-----'))

    def test_sslDerToPem_invalid_cert_should_raise_TypeError(self):
        invalid_types = [None, "", list(), dict()]
        for invalid_type in invalid_types:
            with self.subTest(invalid_type=invalid_type), self.assertRaises(TypeError):
                SpiderFootHelpers.sslDerToPem(invalid_type)

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
