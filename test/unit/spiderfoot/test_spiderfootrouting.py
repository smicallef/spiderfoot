# test_spiderfootrouting.py
import unittest

from spiderfoot.routing import modules_for_target

MODS = {
    "sfp_dns": {"consumes": ["INTERNET_NAME"], "provides": ["IP_ADDRESS"], "labels": []},
    "sfp_ipintel": {"consumes": ["IP_ADDRESS"], "provides": ["GEOINFO"], "labels": []},
    "sfp_mail": {"consumes": ["EMAILADDR"], "provides": ["INTERNET_NAME"], "labels": []},
    "sfp_scan": {"consumes": ["IP_ADDRESS"], "provides": ["TCP_PORT_OPEN"], "labels": ["slow", "invasive"]},
    "sfp_keyed": {"consumes": ["IP_ADDRESS"], "provides": ["RAW_RIR_DATA"], "labels": ["apikey"],
                  "opts": {"api_key": ""}},
    "sfp_keyed_ok": {"consumes": ["IP_ADDRESS"], "provides": ["RAW_RIR_DATA"], "labels": ["apikey"],
                     "opts": {"api_key": "abc"}},
    "sfp_phone": {"consumes": ["PHONE_NUMBER"], "provides": ["COUNTRY_NAME"], "labels": []},
    "sfp__stor_db": {"consumes": ["*"], "provides": [], "labels": []},
}


class TestSpiderFootRouting(unittest.TestCase):

    def test_follows_the_event_chain(self):
        self.assertEqual(["sfp_dns", "sfp_ipintel", "sfp_keyed_ok"], modules_for_target(MODS, "INTERNET_NAME"))

    def test_hop_limit(self):
        self.assertEqual(["sfp_dns"], modules_for_target(MODS, "INTERNET_NAME", max_hops=1))
        self.assertEqual(["sfp_dns", "sfp_ipintel", "sfp_keyed_ok"], modules_for_target(MODS, "INTERNET_NAME", max_hops=2))

    def test_email_pulls_in_domain_modules(self):
        mods = modules_for_target(MODS, "EMAILADDR")
        self.assertIn("sfp_mail", mods)
        self.assertIn("sfp_dns", mods)
        self.assertIn("sfp_ipintel", mods)

    def test_heavy_modules_need_deep(self):
        self.assertNotIn("sfp_scan", modules_for_target(MODS, "IP_ADDRESS"))
        self.assertIn("sfp_scan", modules_for_target(MODS, "IP_ADDRESS", deep=True))

    def test_unkeyed_modules_skipped_unless_allowed(self):
        self.assertNotIn("sfp_keyed", modules_for_target(MODS, "IP_ADDRESS"))
        self.assertIn("sfp_keyed", modules_for_target(MODS, "IP_ADDRESS", allow_unkeyed=True))

    def test_unrelated_modules_not_selected(self):
        self.assertEqual(["sfp_phone"], modules_for_target(MODS, "PHONE_NUMBER"))

    def test_storage_never_routed(self):
        for t in ("INTERNET_NAME", "IP_ADDRESS", "PHONE_NUMBER"):
            self.assertNotIn("sfp__stor_db", modules_for_target(MODS, t))


if __name__ == "__main__":
    unittest.main()
