# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_spamhaus
# Purpose:      SpiderFoot plug-in for looking up whether IPs/Netblocks/Domains
#               appear in the Spamhaus block lists, indicating potential open-relays,
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


class sfp_spamhaus(SpiderFootPlugin):

    meta = {
        'name': "Spamhaus Zen",
        'summary': "Check if a netblock or IP address is in the Spamhaus Zen database.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.spamhaus.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.spamhaus.org/zen/",
                "https://www.spamhaus.org/organization/dnsblusage/",
                "https://www.spamhaus.org/datafeed/",
                "https://www.spamhaus.org/whitepapers/dnsbl_function/",
                "https://www.spamhaus.org/faq/section/DNSBL%20Usage"
            ],
            'favIcon': "https://www.spamhaus.org/favicon.ico",
            'logo': "https://www.spamhaus.org/images/sh_logo1.jpg",
            'description': "The Spamhaus Project is an international nonprofit organization that "
            "tracks spam and related cyber threats such as phishing, malware and botnets, "
            "provides realtime actionable and highly accurate threat intelligence to "
            "the Internet's major networks, corporations and security vendors, "
            "and works with law enforcement agencies to identify and pursue spam and malware sources worldwide. "
            "ZEN is the combination of all Spamhaus IP-based DNSBLs into one single powerful and comprehensive "
            "blocklist to make querying faster and simpler. It contains the SBL, SBLCSS, XBL and PBL blocklists.",
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
    errorState = False

    checks = {
        '127.0.0.2': "Spamhaus (Zen) - Spammer",
        '127.0.0.3': "Spamhaus (Zen) - Spammer",
        '127.0.0.4': "Spamhaus (Zen) - Proxies, Trojans, etc.",
        '127.0.0.5': "Spamhaus (Zen) - Proxies, Trojans, etc.",
        '127.0.0.6': "Spamhaus (Zen) - Proxies, Trojans, etc.",
        '127.0.0.7': "Spamhaus (Zen) - Proxies, Trojans, etc.",
        '127.0.0.10': "Spamhaus (Zen) - Potential Spammer",
        '127.0.0.11': "Spamhaus (Zen) - Potential Spammer",
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.errorState = False
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
        if not self.sf.validIP(ipaddr):
            self.debug(f"Invalid IPv4 address {ipaddr}")
            return None
        return '.'.join(reversed(ipaddr.split('.')))

    def queryAddr(self, qaddr):
        """Query Spamhaus Zen DNS for an IPv4 address.

        Args:
            qaddr (str): IPv4 address.

        Returns:
            list: Spamhaus Zen DNS entries
        """
        if not self.sf.validIP(qaddr):
            self.debug(f"Invalid IPv4 address {qaddr}")
            return None

        try:
            lookup = self.reverseAddr(qaddr) + '.zen.spamhaus.org'
            self.debug(f"Checking Spamhaus Zen blacklist: {lookup}")
            return self.sf.resolveHost(lookup)
        except Exception as e:
            self.debug(f"Spamhaus Zen did not resolve {qaddr} / {lookup}: {e}")

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

            res = self.queryAddr(addr)

            self.results[addr] = True

            if not res:
                continue

            self.debug(f"{addr} found in Spamhaus Zen DNS")

            for result in res:
                k = str(result)

                if k == '127.255.255.252':
                    self.error('Spamhaus rejected malformed request')
                    continue

                if k == '127.255.255.254':
                    self.error('Spamhaus denied query via public/open resolver')
                    self.errorState = True
                    continue

                if k == '127.255.255.255':
                    self.error('Spamhaus rejected query due to excessive number of queries')
                    self.errorState = True
                    continue

                if k not in self.checks:
                    if not k.endswith('.zen.spamhaus.org'):
                        # This is an error. The "checks" dict may need to be updated.
                        self.error(f"Spamhaus Zen resolved address {addr} to unknown IP address {result} not found in Spamhaus Zen list.")
                    continue

                evt = SpiderFootEvent(blacklist_type, f"{self.checks[k]} [{addr}]", self.__name__, event)
                self.notifyListeners(evt)

                evt = SpiderFootEvent(malicious_type, f"{self.checks[k]} [{addr}]", self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_spamhaus class
