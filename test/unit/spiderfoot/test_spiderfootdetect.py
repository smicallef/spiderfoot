# test_spiderfootdetect.py
import unittest

from spiderfoot.detect import detect_target


class TestSpiderFootDetect(unittest.TestCase):

    def check(self, raw, kind, value=None, target_type=None):
        d = detect_target(raw)
        self.assertTrue(d.ok, f"{raw!r}: {d.error}")
        self.assertEqual(kind, d.kind, f"{raw!r} -> {d.kind}")
        if value is not None:
            self.assertEqual(value, d.value)
        if target_type is not None:
            self.assertEqual(target_type, d.target_type)
        return d

    def test_documented_examples(self):
        self.check("example.com", "DOMAIN_NAME", "example.com", "INTERNET_NAME")
        self.check("1.2.3.4", "IP_ADDRESS", "1.2.3.4", "IP_ADDRESS")
        self.check("2606:4700:4700::1111", "IPV6_ADDRESS", "2606:4700:4700::1111", "IPV6_ADDRESS")
        self.check("abc.example.com", "HOSTNAME", "abc.example.com", "INTERNET_NAME")
        self.check("1.2.3.0/24", "NETBLOCK_OWNER", "1.2.3.0/24", "NETBLOCK_OWNER")
        self.check("1HesYJSP1QqcyPEjnQ9vzBL1wujruNGe7R", "BITCOIN_ADDRESS", None, "BITCOIN_ADDRESS")
        self.check("bob@example.com", "EMAILADDR", "bob@example.com", "EMAILADDR")
        self.check("+12345678901", "PHONE_NUMBER", "+12345678901", "PHONE_NUMBER")
        self.check('"John Smith"', "HUMAN_NAME", "John Smith", "HUMAN_NAME")
        self.check('"jsmith2000"', "USERNAME", "jsmith2000", "USERNAME")
        self.check("1234", "BGP_AS_OWNER", "1234", "BGP_AS_OWNER")

    def test_quotes_are_optional_for_obvious_cases(self):
        self.check("John Smith", "HUMAN_NAME", "John Smith")
        self.check("jsmith2000", "USERNAME", "jsmith2000")
        self.check("@jsmith2000", "USERNAME", "jsmith2000")
        self.check("“John Smith”", "HUMAN_NAME", "John Smith")

    def test_quotes_force_intent(self):
        self.check('"example.com"', "USERNAME", "example.com")
        self.check('"1.2.3.4"', "USERNAME", "1.2.3.4")

    def test_asn_forms(self):
        self.check("AS13335", "BGP_AS_OWNER", "13335")
        self.check("as 13335", "BGP_AS_OWNER", "13335")
        d = self.check("13335", "BGP_AS_OWNER", "13335")
        self.assertEqual("high", d.confidence)

    def test_ipv6_is_not_confused_with_hex_words(self):
        self.check("dead", "USERNAME")
        self.check("::1", "IPV6_ADDRESS", "::1")
        self.check("[2001:db8::1]", "IPV6_ADDRESS", "2001:db8::1")
        self.check("2001:db8::/32", "NETBLOCKV6_OWNER", "2001:db8::/32")

    def test_invalid_ipv4_is_not_an_ip(self):
        d = detect_target("999.1.1.1")
        self.assertNotEqual("IP_ADDRESS", d.kind)

    def test_ipv4_extras(self):
        d = self.check("1.2.3.4:8080", "IP_ADDRESS", "1.2.3.4")
        self.assertTrue(any("port" in n for n in d.notes))
        d = self.check("1.2.3.4/24", "NETBLOCK_OWNER", "1.2.3.0/24")
        self.assertTrue(any("Host bits" in n for n in d.notes))

    def test_urls_and_email_wrappers(self):
        d = self.check("https://abc.example.com/path?q=1", "HOSTNAME", "abc.example.com")
        self.assertTrue(any("URL" in n for n in d.notes))
        self.check("http://1.2.3.4/admin", "IP_ADDRESS", "1.2.3.4")
        self.check("mailto:Bob@Example.com", "EMAILADDR", "bob@example.com")
        self.check("Bob Jones <bob@example.com>", "EMAILADDR", "bob@example.com")

    def test_public_suffix_awareness(self):
        self.check("example.co.uk", "DOMAIN_NAME", "example.co.uk")
        self.check("www.example.co.uk", "HOSTNAME", "www.example.co.uk")
        self.check("münchen.de", "DOMAIN_NAME", "xn--mnchen-3ya.de")

    def test_phone_formats(self):
        self.check("+1 (234) 567-8901", "PHONE_NUMBER", "+12345678901")
        self.check("00971 4 123 4567", "PHONE_NUMBER")

    def test_bare_digit_phone_ambiguity(self):
        # Too big for an ASN, so it can only be a phone number missing its +
        d = self.check("971501234567", "PHONE_NUMBER", "+971501234567")
        self.assertIn(d.confidence, ("low", "medium"))
        # Fits in 32 bits and is also a valid Iceland number: ASN wins, phone offered as an alternative
        d = self.check("3545551234", "BGP_AS_OWNER", "3545551234")
        self.assertEqual("medium", d.confidence)
        self.assertEqual("PHONE_NUMBER", d.alternatives[0]["kind"])

    def test_bitcoin_checksum(self):
        d = self.check("1HesYJSP1QqcyPEjnQ9vzBL1wujruNGe7R", "BITCOIN_ADDRESS")
        self.assertEqual("high", d.confidence)
        d = self.check("1HesYJSP1QqcyPEjnQ9vzBL1wujruNGe7S", "BITCOIN_ADDRESS")
        self.assertEqual("low", d.confidence)
        self.check("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "BITCOIN_ADDRESS")

    def test_rejects_garbage(self):
        for bad in ("", "   ", None, "@@@", "a b@@ c / d", '""'):
            self.assertFalse(detect_target(bad).ok, repr(bad))

    def test_result_is_serialisable(self):
        d = detect_target("example.com").to_dict()
        self.assertEqual("Domain Name", d["label"])
        self.assertIn("confidence", d)


if __name__ == "__main__":
    unittest.main()
