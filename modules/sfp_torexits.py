# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_torexits
# Purpose:     Checks if an IP address or netblock appears on the TOR Metrics
#              exit node list.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_torexits(SpiderFootPlugin):

    meta = {
        'name': "TOR Exit Nodes",
        'summary': "Check if an IP adddress or netblock appears on the Tor Metrics exit node list.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Secondary Networks"],
        'dataSource': {
            'website': "https://metrics.torproject.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://metrics.torproject.org/rs.html#search/flag:exit",
            ],
            'favIcon': "https://metrics.torproject.org/images/favicon.ico",
            'logo': "https://metrics.torproject.org/images/tor-metrics-white@2x.png",
            'description': "The relay search tool displays data about single relays and bridges in the Tor network."
        },
    }

    opts = {
        'checkaffiliates': True,
        'cacheperiod': 1,
        'checknetblocks': True,
        'checksubnets': True
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
        'cacheperiod': "Hours to cache list data before re-fetching.",
        'checknetblocks': "Report if any malicious IPs are found within owned netblocks?",
        'checksubnets': "Check if any malicious IPs are found within the same subnet of the target?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.__dataSource__ = "torproject.org"

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
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_SUBNET",
            "MALICIOUS_NETBLOCK"
        ]

    def queryExitNodes(self, target, targetType):
        exit_addresses = self.retrieveExitNodes()

        if not exit_addresses:
            self.errorState = True
            return False

        if targetType == "ip":
            if target in exit_addresses:
                self.debug(f"IP address {target} found in TOR exit node list.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in exit_addresses:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in TOR exit node list.")
                    return True

        return False

    def retrieveExitNodes(self):
        exit_addresses = self.sf.cacheGet('torexitnodes', self.opts.get('cacheperiod', 1))

        if exit_addresses is not None:
            return self.parseExitNodes(exit_addresses)

        res = self.sf.fetchUrl(
            "https://onionoo.torproject.org/details?search=flag:exit",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from onionoo.torproject.org.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from onionoo.torproject.org.")
            self.errorState = True
            return None

        self.sf.cachePut("torexitnodes", res['content'])

        return self.parseExitNodes(res['content'])

    def parseExitNodes(self, data):
        """Extract exit node IP addresses from TOR relay search results

        Args:
            data (str): TOR relay search results

        Returns:
            list: list of TOR exit IP addresses
        """
        ips = list()

        if not data:
            return ips

        try:
            results = json.loads(data)
        except Exception as e:
            self.error(f"Error processing JSON response: {e}")
            return None

        relays = results.get('relays')

        if not relays:
            return ips

        for relay in relays:
            or_addresses = relay.get('or_addresses')

            if or_addresses:
                for ip in or_addresses:
                    # IPv6 addresses are wrapped in [] (For example: "[127.0.0.1]:443")
                    if ip.startswith("["):
                        ip = ip.split('[')[1].split(']')[0]
                        if self.sf.validIP6(ip):
                            ips.append(ip)
                    else:
                        ip = ip.split(':')[0]
                        if self.sf.validIP(ip):
                            ips.append(ip)

            # Exit addresses are only listed in the exit addreses array
            # if the address differs from the OR address.
            exit_addresses = relay.get('exit_addresses')

            if exit_addresses:
                for ip in exit_addresses:
                    if self.sf.validIP(ip) or self.sf.validIP6(ip):
                        ips.append(ip)

        return list(set(ips))

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            targetType = 'ip'
            evtType = 'MALICIOUS_IPADDR'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'ip'
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
        elif eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts.get('checknetblocks', False):
                return
            targetType = 'netblock'
            evtType = 'MALICIOUS_NETBLOCK'
        elif eventName in ['NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            if not self.opts.get('checksubnets', False):
                return
            targetType = 'netblock'
            evtType = 'MALICIOUS_SUBNET'
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        self.debug(f"Checking if {eventData} ({eventName}) is a TOR exit node")

        if self.queryExitNodes(eventData, targetType):
            if targetType == 'ip':
                url = f"https://metrics.torproject.org/rs.html#search/{eventData}"
            else:
                url = "https://metrics.torproject.org/rs.html"
            text = f"TOR Exit Node [{eventData}]\n<SFURL>{url}</SFURL>"
            evt = SpiderFootEvent(evtType, text, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_torexits class
