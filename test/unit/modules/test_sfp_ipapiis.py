import json
import pytest
import unittest
from unittest import mock

from modules.sfp_ipapiis import sfp_ipapiis
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


VPN_RESPONSE = {
    "ip": "85.203.46.163",
    "rir": "RIPE",
    "is_bogon": False,
    "is_mobile": False,
    "is_satellite": False,
    "is_anycast": False,
    "is_crawler": False,
    "is_datacenter": False,
    "is_tor": False,
    "is_proxy": False,
    "is_vpn": True,
    "is_abuser": True,
    "vpn": {
        "ip": "85.203.46.163",
        "service": "Private Internet Access",
        "url": "https://privateinternetaccess.com",
        "type": "exit_node",
        "last_seen": 1791512121028,
        "last_seen_str": "2026-10-09T02:15:21.028Z",
        "exit_node_region": "uk-london",
        "country_code": "GB",
        "city_name": "London",
        "latitude": 51.50853,
        "longitude": -0.12574
    },
    "company": {
        "name": "EXPRESS-EQUINIX-LONDON",
        "abuser_score": "0.3086 (Very High)",
        "domain": "falco-networks.com",
        "type": "business",
        "network": "85.203.46.0 - 85.203.46.255",
        "netname": "Express-Equinix-London"
    },
    "abuse": {
        "name": "Jeroen van veen",
        "address": "Falco IPR B.V., De Hoefsmid 11-13, 1851 PZ Heiloo, The Netherlands",
        "email": "jeroen@falco-networks.com",
        "phone": "+31 72 532 3744"
    },
    "asn": {
        "asn": 212238,
        "abuser_score": "0.0327 (High)",
        "route": "85.203.46.0/24",
        "descr": "CDNEXT - Datacamp Limited, GB",
        "country": "gb",
        "active": True,
        "org": "Datacamp Limited",
        "domain": "cogentco.com",
        "abuse": "abuse@datacamp.co.uk",
        "type": "isp",
        "created": "2020-12-02",
        "updated": "2026-07-14",
        "rir": "RIPE"
    },
    "location": {
        "is_eu_member": False,
        "calling_code": "44",
        "currency_code": "GBP",
        "continent": "EU",
        "country": "United Kingdom",
        "country_code": "GB",
        "state": "England",
        "city": "London",
        "latitude": 51.50853,
        "longitude": -0.12574,
        "zip": "EC1A",
        "timezone": "Europe/London",
        "utcoffset": "+01:00",
        "accuracy": "MEDIUM"
    }
}

DATACENTER_RESPONSE = {
    "ip": "45.33.12.34",
    "is_bogon": False,
    "is_datacenter": True,
    "is_tor": True,
    "is_proxy": True,
    "is_vpn": False,
    "is_abuser": False,
    "datacenter": {
        "datacenter": "Linode",
        "domain": "linode.com",
        "network": "45.33.0.0/17"
    },
    "location": None
}

KEYLESS_RESPONSE = {
    "ip": "187.13.12.227",
    "is_bogon": False,
    "company": "PacketHub S.A.",
    "asn": "AS212238 Datacamp Limited",
    "city": "Bordeaux",
    "region": "New Aquitaine",
    "country": "France",
    "lat": 44.84048,
    "lon": -0.58079,
    "timezone": "Europe/Paris",
    "docs": "https://ipapi.is/free-tier.html?ref=api"
}


@pytest.mark.usefixtures
class TestModuleIpapiis(unittest.TestCase):

    def lookup(self, ip, content, code="200", api_key="example key"):
        sf = SpiderFoot(self.default_options)
        sf.fetchUrl = mock.MagicMock(return_value={'code': code, 'content': content})

        module = sfp_ipapiis()
        events = []
        module.notifyListeners = events.append

        root = SpiderFootEvent('ROOT', ip, '', '')
        evt = SpiderFootEvent('IP_ADDRESS', ip, 'example module', root)

        # setup() writes into the opts dict the class shares with every instance
        with mock.patch.dict(sfp_ipapiis.opts):
            module.setup(sf, {'api_key': api_key, '_fetchtimeout': 5})
            module.setTarget(SpiderFootTarget(ip, 'IP_ADDRESS'))
            module.handleEvent(evt)

        return module, [(e.eventType, e.data) for e in events]

    def test_opts(self):
        module = sfp_ipapiis()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)

        module = sfp_ipapiis()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_ipapiis()
        self.assertIsInstance(module.watchedEvents(), list)

    def test_producedEvents_should_return_list(self):
        module = sfp_ipapiis()
        self.assertIsInstance(module.producedEvents(), list)

    def test_handleEvent_vpn_response_should_return_events(self):
        module, events = self.lookup("85.203.46.163", json.dumps(VPN_RESPONSE))

        self.assertCountEqual(events, [
            ("RAW_RIR_DATA", json.dumps(VPN_RESPONSE)),
            ("GEOINFO", "London, England, United Kingdom"),
            ("PHYSICAL_COORDINATES", "51.50853, -0.12574"),
            ("BGP_AS_MEMBER", "212238"),
            ("VPN_HOST", "85.203.46.163"),
            ("MALICIOUS_IPADDR", "ipapi.is [85.203.46.163]"),
        ])

        args, kwargs = module.sf.fetchUrl.call_args
        self.assertEqual(args[0], "https://api.ipapi.is/")
        self.assertEqual(kwargs['headers']['Content-Type'], "application/json")
        self.assertEqual(json.loads(kwargs['postData']), {"q": "85.203.46.163", "key": "example key"})

    def test_handleEvent_datacenter_response_should_return_events(self):
        module, events = self.lookup("45.33.12.34", json.dumps(DATACENTER_RESPONSE))

        self.assertCountEqual(events, [
            ("RAW_RIR_DATA", json.dumps(DATACENTER_RESPONSE)),
            ("PROVIDER_HOSTING", "Linode"),
            ("PROXY_HOST", "45.33.12.34"),
            ("TOR_EXIT_NODE", "45.33.12.34"),
        ])

    def test_handleEvent_keyless_response_should_return_location_and_asn(self):
        module, events = self.lookup("187.13.12.227", json.dumps(KEYLESS_RESPONSE), api_key="")

        self.assertCountEqual(events, [
            ("RAW_RIR_DATA", json.dumps(KEYLESS_RESPONSE)),
            ("GEOINFO", "Bordeaux, New Aquitaine, France"),
            ("PHYSICAL_COORDINATES", "44.84048, -0.58079"),
            ("BGP_AS_MEMBER", "212238"),
        ])
        self.assertFalse(module.errorState)

        args, kwargs = module.sf.fetchUrl.call_args
        self.assertEqual(json.loads(kwargs['postData']), {"q": "187.13.12.227"})

    def test_handleEvent_bogon_should_not_return_events(self):
        bogon = dict(KEYLESS_RESPONSE, ip="10.0.0.1", is_bogon=True)
        module, events = self.lookup("10.0.0.1", json.dumps(bogon), api_key="")

        self.assertEqual(events, [])

    def test_handleEvent_error_response_should_not_return_events(self):
        responses = [
            ("400", {"error": "Invalid IP Address or AS Number", "error_code": "ERR_INVALID_IP_OR_ASN"}, False),
            ("403", {"error": "Invalid API key. Please register at https://ipapi.is/ to obtain a valid API key", "error_code": "ERR_FORBIDDEN_INVALID_API_KEY"}, True),
            ("429", {"error": "Daily limit reached: 30 free lookups per IP address per day.", "error_code": "ERR_FREE_TIER_EXHAUSTED"}, True),
            ("403", None, True),
        ]

        for code, body, errorState in responses:
            with self.subTest(code=code, body=body):
                content = json.dumps(body) if body else ""
                module, events = self.lookup("85.203.46.163", content, code=code)

                self.assertEqual(events, [])
                self.assertEqual(module.errorState, errorState)
