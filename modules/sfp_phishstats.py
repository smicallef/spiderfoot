# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_phishstats
# Purpose:     Spiderfoot plugin to search PhishStats API
#              to determine if an IP is malicious.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     18/05/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib.error
import urllib.parse
import urllib.request

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_phishstats(SpiderFootPlugin):

    meta = {
        'name': "PhishStats",
        'summary': "Check if a netblock or IP address is malicious according to PhishStats.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://phishstats.info/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://phishstats.info/#apidoc"
            ],
            'favIcon': "https://phishstats.info/phish.ico",
            'description': "PhishStats is a real time Phishing database that gathers phishing URLs from several sources.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24,
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
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
            'IP_ADDRESS',
            'AFFILIATE_IPADDR',
            "NETBLOCK_MEMBER",
            "NETBLOCK_OWNER",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
            "RAW_RIR_DATA",
        ]

    # Check whether the IP address is malicious using PhishStats API
    # https://phishstats.info/
    def queryIPAddress(self, qry):
        params = {
            '_where': f"(ip,eq,{qry})",
            '_size': 1
        }

        headers = {
            'Accept': "application/json",
        }

        res = self.sf.fetchUrl(
            'https://phishstats.info:2096/api/phishing?' + urllib.parse.urlencode(params),
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        if res['code'] != "200":
            self.debug(f"No information found from PhishStats for {qry}.")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == 'IP_ADDRESS':
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return

            max_subnet = self.opts['maxsubnet']
            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            max_netblock = self.opts['maxnetblock']
            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
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

        for addr in qrylist:
            if self.checkForStop():
                return

            data = self.queryIPAddress(addr)

            if not data:
                continue

            # TODO: iterate through hosts and extract co-hosts
            try:
                maliciousIP = data[0].get('ip')
            except Exception:
                # If ArrayIndex is out of bounds then data doesn't exist
                continue

            if not maliciousIP:
                continue

            if addr != maliciousIP:
                self.error(f"Reported address {maliciousIP} doesn't match queried IP address {addr}, skipping")
                continue

            # For netblocks, we need to create the IP address event so that
            # the threat intel event is more meaningful.
            if eventName == 'NETBLOCK_OWNER':
                pevent = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            elif eventName == 'NETBLOCK_MEMBER':
                pevent = SpiderFootEvent("AFFILIATE_IPADDR", addr, self.__name__, event)
                self.notifyListeners(pevent)
            else:
                pevent = event

            evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, pevent)
            self.notifyListeners(evt)

            text = f"PhishStats [{addr}]"

            evt = SpiderFootEvent(blacklist_type, text, self.__name__, pevent)
            self.notifyListeners(evt)

            evt = SpiderFootEvent(malicious_type, text, self.__name__, pevent)
            self.notifyListeners(evt)

# End of sfp_phishstats class
