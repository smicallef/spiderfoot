# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_fraudguard
# Purpose:      Query fraudguard.io using their API
#
# Author:      Steve Micallef
#
# Created:     18/06/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import base64
import json
import time
from datetime import datetime

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_fraudguard(SpiderFootPlugin):

    meta = {
        'name': "Fraudguard",
        'summary': "Obtain threat information from Fraudguard.io",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://fraudguard.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.fraudguard.io/",
                "https://faq.fraudguard.io/"
            ],
            'apiKeyInstructions': [
                "Visit https://app.fraudguard.io/register",
                "Register a free account",
                "Navigate to https://app.fraudguard.io/keys",
                "The API key combination is listed under Username and Password"
            ],
            'favIcon': "https://fraudguard.io/img/favicon.ico",
            'logo': "https://s3.amazonaws.com/fraudguard.io/img/header.png",
            'description': "FraudGuard is a service designed to provide an easy way to validate usage "
            "by continuously collecting and analyzing real-time internet traffic. "
            "Utilizing just a few simple API endpoints we make integration as simple as possible "
            "and return data such as: Risk Level, Threat Type, Geo Location, etc. Super fast, super simple.\n"
            "Lookup any IP address by querying our threat engine.",
        }
    }

    # Default options
    opts = {
        "fraudguard_api_key_account": "",
        "fraudguard_api_key_password": "",
        "age_limit_days": 90,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        'subnetlookup': True,
        'maxsubnet': 24,
        'maxv6subnet': 120,
        'checkaffiliates': True
    }

    # Option descriptions
    optdescs = {
        "fraudguard_api_key_account": "Fraudguard.io API username.",
        "fraudguard_api_key_password": "Fraudguard.io API password.",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum IPv4 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6netblock': "If looking up owned netblocks, the maximum IPv6 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum IPv4 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6subnet': "If looking up subnets, the maximum IPv6 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'checkaffiliates': "Apply checks to affiliates?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.errorState = False
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
        ]

    def producedEvents(self):
        return [
            "GEOINFO",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_SUBNET",
            "MALICIOUS_NETBLOCK"
        ]

    def query(self, qry):
        """Query IP address

        Args:
            qry (str): IPv4/IPv6 address

        Returns:
            dict: JSON formatted results
        """

        fraudguard_url = "https://api.fraudguard.io/ip/" + qry
        api_key_account = self.opts['fraudguard_api_key_account']
        if type(api_key_account) == str:
            api_key_account = api_key_account.encode('utf-8')
        api_key_password = self.opts['fraudguard_api_key_password']
        if type(api_key_password) == str:
            api_key_password = api_key_password.encode('utf-8')
        token = base64.b64encode(api_key_account + ':'.encode('utf-8') + api_key_password)
        headers = {
            'Authorization': "Basic " + token.decode('utf-8')
        }

        res = self.sf.fetchUrl(
            fraudguard_url,
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers
        )

        if res['code'] in ["400", "429", "500", "403"]:
            self.error("Fraudguard.io API key seems to have been rejected or you have exceeded usage limits for the month.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info(f"No Fraudguard.io info found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from Fraudguard.io: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['fraudguard_api_key_account'] == "" or self.opts['fraudguard_api_key_password'] == "":
            self.error("You enabled sfp_fraudguard but did not set an API username/password!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
            return

        if eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts['netblocklookup']:
                return

            if eventName == 'NETBLOCKV6_OWNER':
                max_netblock = self.opts['maxv6netblock']
            else:
                max_netblock = self.opts['maxnetblock']

            max_netblock = self.opts['maxnetblock']
            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

        if eventName in ['NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            if not self.opts['subnetlookup']:
                return

            if eventName == 'NETBLOCKV6_MEMBER':
                max_subnet = self.opts['maxv6subnet']
            else:
                max_subnet = self.opts['maxsubnet']

            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS', 'NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            evtType = 'MALICIOUS_IPADDR'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS', 'NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        qrylist = list()
        if eventName.startswith("NETBLOCK"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)
            self.results[eventData] = True

        for addr in qrylist:
            if self.checkForStop():
                return

            data = self.query(addr)

            if not data:
                continue

            self.debug(f"Found results for {addr} in Fraudguard.io")

            # Format: 2016-12-24T07:25:35+00:00'
            created_dt = datetime.strptime(data.get('discover_date'), '%Y-%m-%d %H:%M:%S')
            created_ts = int(time.mktime(created_dt.timetuple()))
            age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
            if self.opts['age_limit_days'] > 0 and created_ts < age_limit_ts:
                self.debug(f"Record found but too old ({created_dt}), skipping.")
                continue

            # For netblocks, we need to create the IP address event so that
            # the threat intel event is more meaningful.
            if eventName == 'NETBLOCK_OWNER':
                pevent = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            if eventName == 'NETBLOCKV6_OWNER':
                pevent = SpiderFootEvent("IPV6_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            elif eventName == 'NETBLOCK_MEMBER':
                pevent = SpiderFootEvent("AFFILIATE_IPADDR", addr, self.__name__, event)
                self.notifyListeners(pevent)
            elif eventName == 'NETBLOCKV6_MEMBER':
                pevent = SpiderFootEvent("AFFILIATE_IPV6_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            else:
                pevent = event

            geoinfo = [
                _f for _f in [
                    data.get('state'),
                    data.get('city'),
                    data.get('postal_code'),
                    data.get('country')
                ] if _f and _f != "unknown"
            ]
            if geoinfo:
                location = ', '.join(filter(None, geoinfo))
                e = SpiderFootEvent("GEOINFO", location, self.__name__, pevent)
                self.notifyListeners(e)

            threat = data.get('threat')
            if threat and threat != "unknown":
                risk_level = data.get('risk_level')
                e = SpiderFootEvent(evtType, f"{threat} (risk level: {risk_level}) [{addr}]", self.__name__, pevent)
                self.notifyListeners(e)

# End of sfp_fraudguard class
