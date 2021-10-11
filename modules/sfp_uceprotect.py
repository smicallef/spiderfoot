# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_uceprotect
# Purpose:      SpiderFoot plug-in for looking up whether IPs/Netblocks/Domains
#               appear in the UCEPROTECT blacklist, indicating potential open-relays,
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


class sfp_uceprotect(SpiderFootPlugin):

    meta = {
        'name': "UCEPROTECT",
        'summary': "Check if a netblock or IP address is in the UCEPROTECT database.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://www.uceprotect.net/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "http://www.uceprotect.net/en/index.php?m=3&s=3",
                "http://www.uceprotect.net/en/index.php?m=6&s=0",
                "http://www.uceprotect.net/en/index.php?m=6&s=11",
                "http://www.uceprotect.net/en/index.php?m=13&s=0",
                "http://www.uceprotect.net/en/rblcheck.php"
            ],
            'favIcon': "https://www.uceprotect.net/favicon.ico",
            'logo': "https://www.uceprotect.net/en/logo.gif",
            'description': "UCEPROTECT is a DNS blacklisting service whose mission is to stop mail abuse globally.",
        }
    }

    opts = {
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
    }

    optdescs = {
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    results = None

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
        ]

    # Swap 1.2.3.4 to 4.3.2.1
    def reverseAddr(self, ipaddr):
        return '.'.join(reversed(ipaddr.split('.')))

    def queryDnsblLevel1(self, qaddr):
        """Query UCEPROTECT DNS Level 1 for an IPv4 address.

        Args:
            qaddr (str): IPv4 address.

        Returns:
            list: UCEPROTECT DNS entries
        """
        if not self.sf.validIP(qaddr):
            self.debug(f"Invalid IPv4 address {qaddr}")
            return None

        try:
            lookup = self.reverseAddr(qaddr) + '.dnsbl-1.uceprotect.net'
            self.debug(f"Checking UCEPROTECT blacklist: {lookup}")
            return self.sf.resolveHost(lookup)
        except Exception as e:
            self.debug(f"UCEPROTECT did not resolve {qaddr} / {lookup}: {e}")

        return None

    def queryDnsblLevel2(self, qaddr):
        """Query UCEPROTECT DNS Level 2 for an IPv4 address.

        Args:
            qaddr (str): IPv4 address.

        Returns:
            list: UCEPROTECT DNS entries
        """
        if not self.sf.validIP(qaddr):
            self.debug(f"Invalid IPv4 address {qaddr}")
            return None

        try:
            lookup = self.reverseAddr(qaddr) + '.dnsbl-2.uceprotect.net'
            self.debug(f"Checking UCEPROTECT blacklist: {lookup}")
            return self.sf.resolveHost(lookup)
        except Exception as e:
            self.debug(f"UCEPROTECT did not resolve {qaddr} / {lookup}: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventName == "AFFILIATE_IPADDR":
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName == "IP_ADDRESS":
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

        addrs = list()
        if eventName.startswith("NETBLOCK_"):
            for addr in IPNetwork(eventData):
                addrs.append(str(addr))
        else:
            addrs.append(eventData)

        for addr in addrs:
            if self.checkForStop():
                return

            level1 = self.queryDnsblLevel1(addr)
            level2 = self.queryDnsblLevel2(addr)

            self.results[addr] = True

            if not level1 and not level2:
                continue

            self.debug(f"{addr} found in UCEPROTECT DNS")

            url = f"https://www.uceprotect.net/en/rblcheck.php?ipr={addr}"

            if level1:
                description = f"UCEPROTECT - Level 1 (high likelihood) [{addr}]\n<SFURL>{url}</SFURL>"
                evt = SpiderFootEvent(blacklist_type, description, self.__name__, event)
                self.notifyListeners(evt)

                evt = SpiderFootEvent(malicious_type, description, self.__name__, event)
                self.notifyListeners(evt)

            if level2:
                description = f"UCEPROTECT - Level 2 (some false positives) [{addr}]\n<SFURL>{url}</SFURL>"

                evt = SpiderFootEvent(blacklist_type, description, self.__name__, event)
                self.notifyListeners(evt)

                evt = SpiderFootEvent(malicious_type, description, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_uceprotect class
