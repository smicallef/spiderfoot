# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ipapiis
# Purpose:     SpiderFoot plug-in to look up geolocation, network owner and
#              VPN, proxy, Tor, datacenter and abuser detection for IP
#              addresses using ipapi.is.
#
# Author:      Nikolai Tschacher <info@ipapi.is>
#
# Created:     2026-10-14
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ipapiis(SpiderFootPlugin):

    meta = {
        'name': "ipapi.is",
        'summary': "Obtain geolocation, network owner, abuse contact and VPN, proxy, Tor, datacenter and abuser detection for IP addresses from ipapi.is.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://ipapi.is/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://ipapi.is/developers.html"
            ],
            'apiKeyInstructions': [
                "Visit https://ipapi.is/app/signup?ref=spiderfoot",
                "Register a free account",
                "Copy the API key from the dashboard at https://ipapi.is/app/home"
            ],
            'favIcon': "https://ipapi.is/img/favicon/favicon-32x32.png",
            'logo': "https://ipapi.is/img/logo-variants/nl5.png",
            'description': "ipapi.is is an IP address intelligence API. "
            "For an IPv4 or IPv6 address it returns the geolocation, the organization and ASN that own it with their abuse contact, "
            "and whether it belongs to a datacenter, VPN, proxy or Tor exit node or was recently seen in abuse. "
            "A free account includes 1,000 lookups per day; without an API key, 30 lookups per day return location and network owner only.",
        }
    }

    opts = {
        'api_key': '',
    }

    optdescs = {
        'api_key': "ipapi.is API key. Optional: without a key, ipapi.is allows 30 lookups per day from your IP address "
        "and returns location and network owner only, without VPN, proxy, Tor, datacenter and abuser detection.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS"
        ]

    def producedEvents(self):
        return [
            "BGP_AS_MEMBER",
            "GEOINFO",
            "MALICIOUS_IPADDR",
            "PHYSICAL_COORDINATES",
            "PROVIDER_HOSTING",
            "PROXY_HOST",
            "RAW_RIR_DATA",
            "TOR_EXIT_NODE",
            "VPN_HOST"
        ]

    def query(self, qry):
        """Look up an IP address on ipapi.is.

        Args:
            qry (str): IPv4 or IPv6 address

        Returns:
            dict: JSON response
        """
        params = {'q': qry}
        if self.opts['api_key']:
            params['key'] = self.opts['api_key']

        res = self.sf.fetchUrl(
            "https://api.ipapi.is/",
            postData=json.dumps(params),
            headers={'Content-Type': "application/json"},
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )

        # ipapi.is bans clients at the firewall that keep sending after a 403 or 429
        if res['code'] in ["403", "429"]:
            self.errorState = True

        try:
            data = json.loads(res['content'])
        except Exception:
            self.error(f"Unexpected response from ipapi.is (HTTP {res['code']})")
            return None

        if data.get('error'):
            self.error(f"ipapi.is error: {data['error']}")
            return None

        return data

    def emit(self, eventType, data, pevent):
        evt = SpiderFootEvent(eventType, data, self.__name__, pevent)
        self.notifyListeners(evt)

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData)

        if not data or data.get('is_bogon'):
            return

        self.emit("RAW_RIR_DATA", json.dumps(data), event)

        # Without an API key the response is flat: company and asn are strings
        # and the location fields sit at the top level.
        location = data.get('location')
        if isinstance(location, dict):
            place = [location.get('city'), location.get('state'), location.get('country')]
            latitude, longitude = location.get('latitude'), location.get('longitude')
        else:
            place = [data.get('city'), data.get('region'), data.get('country')]
            latitude, longitude = data.get('lat'), data.get('lon')

        geoinfo = ', '.join(filter(None, place))
        if geoinfo:
            self.emit("GEOINFO", geoinfo, event)

        if latitude is not None and longitude is not None:
            self.emit("PHYSICAL_COORDINATES", f"{latitude}, {longitude}", event)

        asn = data.get('asn')
        if isinstance(asn, dict):
            asn = asn.get('asn')
        elif asn:
            match = re.match(r"AS(\d+)", asn)
            asn = match.group(1) if match else None
        if asn:
            self.emit("BGP_AS_MEMBER", str(asn), event)

        datacenter = data.get('datacenter') or {}
        if datacenter.get('datacenter'):
            self.emit("PROVIDER_HOSTING", datacenter['datacenter'], event)

        if data.get('is_vpn'):
            self.emit("VPN_HOST", eventData, event)

        if data.get('is_proxy'):
            self.emit("PROXY_HOST", eventData, event)

        if data.get('is_tor'):
            self.emit("TOR_EXIT_NODE", eventData, event)

        if data.get('is_abuser'):
            self.emit("MALICIOUS_IPADDR", f"ipapi.is [{eventData}]", event)

# End of sfp_ipapiis class
