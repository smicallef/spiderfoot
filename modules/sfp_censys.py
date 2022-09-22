# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_censys
# Purpose:     Query Censys.io API
#
# Author:      Steve Micallef
#
# Created:     01/02/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     MIT
# -------------------------------------------------------------------------------

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_censys(SpiderFootPlugin):

    meta = {
        'name': "Censys",
        'summary': "Obtain host information from Censys.io.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://censys.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://search.censys.io/api",
                "https://search.censys.io/search/language",
                "https://github.com/censys/censys-postman/blob/main/Censys_Search.postman_collection.json",
            ],
            'apiKeyInstructions': [
                "Visit https://censys.io/",
                "Register a free account",
                "Navigate to https://censys.io/account",
                "Click on 'API'",
                "The API key combination is listed under 'API ID' and 'Secret'"
            ],
            'favIcon': "https://censys.io/assets/favicon.png",
            'logo': "https://censys.io/assets/logo.png",
            'description': "Discover exposures and other common entry points for attackers.\n"
            "Censys scans the entire internet constantly, including obscure ports. "
            "We use a combination of banner grabs and deep protocol handshakes "
            "to provide industry-leading visibility and an accurate depiction of what is live on the internet.",
        }
    }

    opts = {
        "censys_api_key_uid": "",
        "censys_api_key_secret": "",
        'delay': 3,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        "age_limit_days": 90,
    }

    optdescs = {
        "censys_api_key_uid": "Censys.io API UID.",
        "censys_api_key_secret": "Censys.io API Secret.",
        'delay': 'Delay between requests, in seconds.',
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6netblock': "If looking up owned netblocks, the maximum IPv6 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
        ]

    def producedEvents(self):
        return [
            "BGP_AS_MEMBER",
            "UDP_PORT_OPEN",
            "TCP_PORT_OPEN",
            "TCP_PORT_OPEN_BANNER",
            "OPERATING_SYSTEM",
            "SOFTWARE_USED",
            "WEBSERVER_HTTPHEADERS",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "GEOINFO",
            "RAW_RIR_DATA"
        ]

    def queryHosts(self, qry):
        secret = self.opts['censys_api_key_uid'] + ':' + self.opts['censys_api_key_secret']
        auth = base64.b64encode(secret.encode('utf-8')).decode('utf-8')

        headers = {
            'Authorization': f"Basic {auth}"
        }

        res = self.sf.fetchUrl(
            f"https://search.censys.io/api/v2/hosts/{qry}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers
        )

        # API rate limit: 0.4 actions/second (120.0 per 5 minute interval)
        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    def queryHostsSearch(self, qry):
        secret = self.opts['censys_api_key_uid'] + ':' + self.opts['censys_api_key_secret']
        auth = base64.b64encode(secret.encode('utf-8')).decode('utf-8')

        headers = {
            'Authorization': f"Basic {auth}"
        }

        params = urllib.parse.urlencode({
            'q': qry,
        })

        res = self.sf.fetchUrl(
            f"https://search.censys.io/api/v2/hosts/search/?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers
        )

        # API rate limit: 0.4 actions/second (120.0 per 5 minute interval)
        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    def parseApiResponse(self, res: dict):
        if not res:
            self.error("No response from Censys.io.")
            return None

        if res['code'] == "400":
            self.error("Invalid request.")
            return None

        if res['code'] == "404":
            self.info('Censys.io returned no results')
            return None

        if res['code'] == "403":
            self.error("Invalid API key.")
            self.errorState = True
            return None

        if res['code'] == "429":
            self.error("Request rate limit exceeded.")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error(f"Unexpected HTTP response code {res['code']} from Censys API.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info('Censys.io returned no results')
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from Censys.io: {e}")
            return None

        error_type = data.get('error_type')
        if error_type:
            self.error(f"Censys returned an unexpected error: {error_type}")
            return None

        return data

    def handleEvent(self, event):
        if self.errorState:
            return

        eventName = event.eventType

        self.debug(f"Received event, {eventName}, from {event.module}")

        if self.opts['censys_api_key_uid'] == "" or self.opts['censys_api_key_secret'] == "":
            self.error(f"You enabled {self.__class__.__name__} but did not set an API uid/secret!")
            self.errorState = True
            return

        eventData = event.data

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts['netblocklookup']:
                return

            if eventName == 'NETBLOCKV6_OWNER':
                max_netblock = self.opts['maxv6netblock']
            else:
                max_netblock = self.opts['maxnetblock']

            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

        qrylist = list()
        if eventName.startswith("NETBLOCK"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        for addr in qrylist:
            if self.checkForStop():
                return

            data = self.queryHosts(addr)

            if not data:
                continue

            rec = data.get("result")

            if not rec:
                self.info(f"Censys.io returned no results for {addr}")
                continue

            self.debug(f"Found results for {addr} in Censys.io")

            # For netblocks, we need to create the associated IP address event first.
            if eventName == 'NETBLOCK_OWNER':
                pevent = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            elif eventName == 'NETBLOCKV6_OWNER':
                pevent = SpiderFootEvent("IPV6_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            else:
                pevent = event

            e = SpiderFootEvent("RAW_RIR_DATA", json.dumps(rec), self.__name__, pevent)
            self.notifyListeners(e)

            try:
                # Date format: 2021-09-22T16:46:47.623Z
                created_dt = datetime.strptime(rec.get('last_updated_at', "1970-01-01T00:00:00.000Z"), '%Y-%m-%dT%H:%M:%S.%fZ')
                created_ts = int(time.mktime(created_dt.timetuple()))
                age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])

                if self.opts['age_limit_days'] > 0 and created_ts < age_limit_ts:
                    self.debug(f"Record found but too old ({created_dt}), skipping.")
                    continue
            except Exception as e:
                self.error(f"Error encountered processing last_updated_at record for {addr}: {e}")

            try:
                location = rec.get('location')
                if location:
                    geoinfo = ', '.join(
                        [
                            _f for _f in [
                                location.get('city'),
                                location.get('province'),
                                location.get('postal_code'),
                                location.get('country'),
                                location.get('continent'),
                            ] if _f
                        ]
                    )
                    if geoinfo:
                        e = SpiderFootEvent("GEOINFO", geoinfo, self.__name__, pevent)
                        self.notifyListeners(e)
            except Exception as e:
                self.error(f"Error encountered processing location record for {addr}: {e}")

            try:
                services = rec.get('services')
                if services:
                    softwares = list()
                    tcp_banners = list()
                    for service in services:
                        port = service.get('port')

                        if port:
                            transport_protocol = service.get('transport_protocol')
                            banner = service.get('banner')

                            if transport_protocol == "UDP":
                                evt = SpiderFootEvent("UDP_PORT_OPEN", f"{addr}:{port}", self.__name__, pevent)
                                self.notifyListeners(evt)
                            elif transport_protocol == "TCP":
                                evt = SpiderFootEvent("TCP_PORT_OPEN", f"{addr}:{port}", self.__name__, pevent)
                                self.notifyListeners(evt)
                                if banner:
                                    tcp_banners.append(banner)

                        software = service.get('software', list())
                        if software:
                            for sw in software:
                                s = ' '.join(
                                    filter(
                                        None,
                                        [
                                            sw.get('vendor'),
                                            sw.get('product'),
                                            sw.get('version')
                                        ]
                                    )
                                )
                                if s:
                                    softwares.append(s)

                        http = service.get('http')
                        if http:
                            response = http.get('response')
                            if response:
                                headers = response.get('headers')
                                if headers:
                                    e = SpiderFootEvent(
                                        "WEBSERVER_HTTPHEADERS",
                                        json.dumps(headers, ensure_ascii=False),
                                        self.__name__,
                                        pevent
                                    )
                                    e.actualSource = addr
                                    self.notifyListeners(e)

                    for software in set(softwares):
                        evt = SpiderFootEvent("SOFTWARE_USED", software, self.__name__, pevent)
                        self.notifyListeners(evt)

                    for banner in set(tcp_banners):
                        evt = SpiderFootEvent("TCP_PORT_OPEN_BANNER", str(banner), self.__name__, pevent)
                        self.notifyListeners(evt)
            except Exception as e:
                self.error(f"Error encountered processing services record for {addr}: {e}")

            try:
                autonomous_system = rec.get('autonomous_system')
                if autonomous_system:
                    asn = autonomous_system.get('asn')
                    if asn:
                        e = SpiderFootEvent("BGP_AS_MEMBER", str(asn), self.__name__, pevent)
                        self.notifyListeners(e)

                    bgp_prefix = autonomous_system.get('bgp_prefix')
                    if bgp_prefix and self.sf.validIpNetwork(bgp_prefix):
                        if ':' in bgp_prefix:
                            e = SpiderFootEvent("NETBLOCKV6_MEMBER", str(bgp_prefix), self.__name__, pevent)
                        else:
                            e = SpiderFootEvent("NETBLOCK_MEMBER", str(bgp_prefix), self.__name__, pevent)
                        self.notifyListeners(e)
            except Exception as e:
                self.error(f"Error encountered processing autonomous_system record for {addr}: {e}")

            try:
                operating_system = rec.get('operating_system')
                if operating_system:
                    os = ' '.join(
                        filter(
                            None,
                            [
                                operating_system.get('vendor'),
                                operating_system.get('product'),
                                operating_system.get('version'),
                                operating_system.get('edition')
                            ]
                        )
                    )

                    if os:
                        e = SpiderFootEvent("OPERATING_SYSTEM", os, self.__name__, pevent)
                        self.notifyListeners(e)
            except Exception as e:
                self.error(f"Error encountered processing operating_system record for {addr}: {e}")

# End of sfp_censys class
