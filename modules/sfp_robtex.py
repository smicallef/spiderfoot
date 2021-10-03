# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_robtex
# Purpose:      Searches Robtex.com for hosts sharing the same IP.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_robtex(SpiderFootPlugin):

    meta = {
        'name': "Robtex",
        'summary': "Search Robtex.com for hosts sharing the same IP.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "https://www.robtex.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.robtex.com/api/"
            ],
            'favIcon': "https://www.robtex.com/favicon.ico",
            'logo': "https://www.robtex.com/favicon.ico",
            'description': "Robtex is used for various kinds of research of IP numbers, Domain names, etc\n"
            "Robtex uses various sources to gather public information about "
            "IP numbers, domain names, host names, Autonomous systems, routes etc. "
            "It then indexes the data in a big database and provide free access to the data.",
        }
    }

    # Default options
    opts = {
        'verify': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        'cohostsamedomain': False,
        'maxcohost': 100,
        'subnetlookup': False,
        'maxsubnet': 24,
        'maxv6subnet': 120,
    }

    # Option descriptions
    optdescs = {
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible co-hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6netblock': "If looking up owned netblocks, the maximum IPv6 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6subnet': "If looking up subnets, the maximum IPv6 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
    }

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.cohostcount = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
        ]

    # What events this module produces
    def producedEvents(self):
        return ["CO_HOSTED_SITE", "IP_ADDRESS", "IPV6_ADDRESS", "RAW_RIR_DATA"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.cohostcount > self.opts['maxcohost']:
            return

        if srcModuleName == "sfp_robtex":
            self.debug(f"Ignoring {eventName}, from self.")
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
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
            self.results[eventData] = True

        retries = 3
        for ip in qrylist:
            retry = 0
            while retry < retries:
                if self.checkForStop():
                    return

                res = self.sf.fetchUrl("https://freeapi.robtex.com/ipquery/" + ip, timeout=self.opts['_fetchtimeout'])

                if res['code'] == "200":
                    break

                if res['code'] == "404":
                    continue

                if res['code'] == "429":
                    # Back off a little further
                    time.sleep(2)

                retry += 1

            if res['content'] is None:
                self.error("No reply from robtex API.")
                continue

            try:
                data = json.loads(res['content'])
            except Exception as e:
                self.error(f"Error parsing JSON from Robtex API: {e}")
                return

            if not data:
                continue

            status = data.get("status")

            if status and status == "ratelimited":
                self.error("You are being rate-limited by robtex API.")
                self.errorState = True
                continue

            evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
            self.notifyListeners(evt)

            pas = data.get('pas')

            if not pas:
                self.info(f"No results from robtex API for {ip}")
                continue

            if not len(pas):
                continue

            for r in data.get('pas'):
                host = r.get('o')

                if not host:
                    continue

                if not self.opts['cohostsamedomain']:
                    if self.getTarget().matches(host, includeParents=True):
                        self.debug(f"Skipping {host} because it is on the same domain.")
                        continue

                if self.opts['verify'] and not self.sf.validateIP(host, ip):
                    self.debug(f"Host {host} no longer resolves to {ip}")
                    continue

                if eventName == "NETBLOCK_OWNER":
                    ipe = SpiderFootEvent("IP_ADDRESS", ip, self.__name__, event)
                    self.notifyListeners(ipe)
                    evt = SpiderFootEvent("CO_HOSTED_SITE", host, self.__name__, ipe)
                    self.notifyListeners(evt)
                elif eventName == "NETBLOCKV6_OWNER":
                    ipe = SpiderFootEvent("IPV6_ADDRESS", ip, self.__name__, event)
                    self.notifyListeners(ipe)
                    evt = SpiderFootEvent("CO_HOSTED_SITE", host, self.__name__, ipe)
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent("CO_HOSTED_SITE", host, self.__name__, event)
                    self.notifyListeners(evt)

                self.cohostcount += 1

# End of sfp_robtex class
