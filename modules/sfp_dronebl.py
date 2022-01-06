# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dronebl
# Purpose:      SpiderFoot plug-in for looking up whether IPs/Netblocks/Domains
#               appear in the DroneBL blocklist, indicating potential open-relays,
#               open proxies, malicious servers, vulnerable servers, etc.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/01/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_dronebl(SpiderFootPlugin):

    meta = {
        'name': "DroneBL",
        'summary': "Query the DroneBL database for open relays, open proxies, vulnerable servers, etc.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://dronebl.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://dronebl.org/docs/howtouse",
                "https://dronebl.org/rpckey_signup",
                "https://dronebl.org/docs/rpc2"
            ],
            'favIcon': "https://dronebl.org/images/favicon.ico",
            'logo': "https://dronebl.org/images/dronebl-logo.svg",
            'description': "DroneBL is a realtime monitor of abusable IPs, which has "
            "the goal of stopping abuse of infected machines.\n"
            "A real-time tracker of abusable IPs.",
        }
    }

    # Default options
    opts = {
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
    }

    # Option descriptions
    optdescs = {
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    results = None

    checks = {
        "127.0.0.3": "dronebl.org - IRC Drone",
        "127.0.0.5": "dronebl.org - Bottler",
        "127.0.0.6": "dronebl.org - Unknown spambot or drone",
        "127.0.0.7": "dronebl.org - DDOS Drone",
        "127.0.0.8": "dronebl.org - SOCKS Proxy",
        "127.0.0.9": "dronebl.org - HTTP Proxy",
        "127.0.0.10": "dronebl.org - ProxyChain",
        "127.0.0.11": "dronebl.org - Web Page Proxy",
        "127.0.0.12": "dronebl.org - Open DNS Resolver",
        "127.0.0.13": "dronebl.org - Brute force attackers",
        "127.0.0.14": "dronebl.org - Open Wingate Proxy",
        "127.0.0.15": "dronebl.org - Compromised router / gateway",
        "127.0.0.16": "dronebl.org - Autorooting worms",
        "127.0.0.17": "dronebl.org - Automatically determined botnet IPs (experimental)",
        "127.0.0.18": "dronebl.org - Possibly compromised DNS/MX",
        "127.0.0.19": "dronebl.org - Abused VPN Service",
        "127.0.0.255": "dronebl.org - Unknown"
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'IP_ADDRESS',
            'AFFILIATE_IPADDR',
            'NETBLOCK_OWNER',
            'NETBLOCK_MEMBER'
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
            "VPN_HOST",
            "PROXY_HOST"
        ]

    # Swap 1.2.3.4 to 4.3.2.1
    def reverseAddr(self, ipaddr):
        if not self.sf.validIP(ipaddr):
            self.debug(f"Invalid IPv4 address {ipaddr}")
            return None
        return '.'.join(reversed(ipaddr.split('.')))

    def queryAddr(self, qaddr):
        """Query DroneBL DNS for an IPv4 address.

        Args:
            qaddr (str): IPv4 address.

        Returns:
            list: DroneBL DNS entries
        """
        if not self.sf.validIP(qaddr):
            self.debug(f"Invalid IPv4 address {qaddr}")
            return None

        try:
            lookup = self.reverseAddr(qaddr) + '.dnsbl.dronebl.org'
            self.debug(f"Checking DroneBL blacklist: {lookup}")
            return self.sf.resolveHost(lookup)
        except Exception as e:
            self.debug(f"DroneBL did not resolve {qaddr} / {lookup}: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            max_netblock = self.opts['maxnetblock']
            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return

            max_subnet = self.opts['maxsubnet']
            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

        if eventName == "AFFILIATE_IPADDR":
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == "IP_ADDRESS":
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == "NETBLOCK_OWNER":
            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
        elif eventName == "NETBLOCK_MEMBER":
            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        addrs = list()
        if eventName.startswith("NETBLOCK_"):
            for addr in IPNetwork(eventData):
                addrs.append(str(addr))
        else:
            addrs.append(eventData)

        for addr in addrs:
            if self.checkForStop():
                return

            res = self.queryAddr(addr)

            self.results[addr] = True

            if not res:
                continue

            self.debug(f"{addr} found in DroneBL DNS: {res}")

            for result in res:
                k = str(result)
                if k not in self.checks:
                    if not result.endswith('.dnsbl.dronebl.org'):
                        # This is an error. The "checks" dict may need to be updated.
                        self.error(f"DroneBL resolved address {addr} to unknown IP address {result} not found in DroneBL list.")
                    continue

                evt = SpiderFootEvent(blacklist_type, f"{self.checks[k]} [{addr}]", self.__name__, event)
                self.notifyListeners(evt)

                if k in [
                    "127.0.0.3",
                    "127.0.0.5",
                    "127.0.0.6",
                    "127.0.0.7",
                    "127.0.0.13",
                    "127.0.0.15",
                    "127.0.0.16",
                    "127.0.0.17",
                    "127.0.0.18",
                    "127.0.0.19",
                ]:
                    evt = SpiderFootEvent(malicious_type, f"{self.checks[k]} [{addr}]", self.__name__, event)
                    self.notifyListeners(evt)

                if k in ["127.0.0.8", "127.0.0.9", "127.0.0.10", "127.0.0.11", "127.0.0.14"]:
                    evt = SpiderFootEvent("PROXY_HOST", addr, self.__name__, event)
                    self.notifyListeners(evt)

                if k == "127.0.0.19":
                    evt = SpiderFootEvent("VPN_HOST", addr, self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_dronebl class
