# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_pulsedive
# Purpose:      Query Pulsedive's API
#
# Author:      Steve Micallef
#
# Created:     04/09/2018
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_pulsedive(SpiderFootPlugin):

    meta = {
        'name': "Pulsedive",
        'summary': "Obtain information from Pulsedive's API.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://pulsedive.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://pulsedive.com/api/"
            ],
            'apiKeyInstructions': [
                "Visit https://pulsedive.com",
                "Register a free account",
                "Navigate to https://pulsedive.com/account",
                "The API key is listed under 'Your API Key'"
            ],
            'favIcon': "https://pulsedive.com/favicon.ico?v=3.9.72",
            'logo': "https://pulsedive.com/img/logo.svg",
            'description': "Why check 30 different solutions for varying snippets of data when you can just check one? "
            "Pulsedive enriches IOCs but also fetches article summaries from Wikipedia and "
            "even posts from Reddit and the infosec blogosphere to provide contextual information for threats.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        # The rate limit for free users is 30 requests per minute
        "delay": 2,
        "age_limit_days": 30,
        'checkaffiliates': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        'subnetlookup': True,
        'maxsubnet': 24,
        'maxv6subnet': 120,
    }

    # Option descriptions
    optdescs = {
        "api_key": "Pulsedive API Key.",
        "delay": "Delay between requests, in seconds.",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
        "checkaffiliates": "Apply checks to affiliates?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum IPv4 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6netblock': "If looking up owned netblocks, the maximum IPv6 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum IPv4 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6subnet': "If looking up subnets, the maximum IPv6 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
            "INTERNET_NAME",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
        ]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_INTERNET_NAME", "MALICIOUS_IPADDR",
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_NETBLOCK",
                'TCP_PORT_OPEN']

    # https://pulsedive.com/api/
    def query(self, qry):
        params = {
            'indicator': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'key': self.opts['api_key']
        }

        url = 'https://pulsedive.com/api/info.php?' + urllib.parse.urlencode(params)
        res = self.sf.fetchUrl(url, timeout=30, useragent="SpiderFoot")

        time.sleep(self.opts['delay'])

        if res['code'] == '429':
            self.error("You are being rate-limited by Pulsedive")
            self.errorState = True
            return None

        if res['code'] == "403":
            self.error("Pulsedive API key seems to have been rejected or you have exceeded usage limits for the month.")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from Pulsedive: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_pulsedive but did not set an API key!")
            self.errorState = True
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

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

        qrylist = list()

        if eventName.startswith("NETBLOCK"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS', 'NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            evtType = 'MALICIOUS_IPADDR'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS', 'NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
        elif eventName == "INTERNET_NAME":
            evtType = 'MALICIOUS_INTERNET_NAME'
        else:
            return

        for addr in qrylist:
            if self.checkForStop():
                return

            rec = self.query(addr)

            if rec is None:
                continue

            attributes = rec.get('attributes')

            if attributes:
                ports = attributes.get('port')
                if ports:
                    for p in ports:
                        e = SpiderFootEvent('TCP_PORT_OPEN', addr + ':' + p, self.__name__, event)
                        self.notifyListeners(e)

            threats = rec.get('threats')

            if not threats:
                continue

            self.debug(f"Found threat info for {addr} in Pulsedive")

            for result in threats:
                descr = addr
                tid = str(rec.get("iid"))
                descr += "\n - " + result.get("name", "")
                descr += " (" + result.get("category", "") + ")"

                if tid:
                    descr += "\n<SFURL>https://pulsedive.com/indicator/?iid=" + tid + "</SFURL>"

                created = result.get("stamp_linked", "")
                # 2018-02-20 03:51:59
                try:
                    created_dt = datetime.strptime(created, '%Y-%m-%d %H:%M:%S')
                    created_ts = int(time.mktime(created_dt.timetuple()))
                    age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                    if self.opts['age_limit_days'] > 0 and created_ts < age_limit_ts:
                        self.debug(f"Threat found but too old ({created_dt}), skipping.")
                        continue
                except Exception:
                    self.debug("Couldn't parse date from Pulsedive so assuming it's OK.")
                e = SpiderFootEvent(evtType, descr, self.__name__, event)
                self.notifyListeners(e)

# End of sfp_pulsedive class
