# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_abusix
# Purpose:     SpiderFoot plug-in for looking up whether IPs/Netblocks/Domains
#              appear in the Abusix Mail Intelligence blacklist.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-10-17
# Copyright:   (c) bcoles 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import ipaddress

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_abusix(SpiderFootPlugin):

    meta = {
        'name': "Abusix Mail Intelligence",
        'summary': "Check if a netblock or IP address is in the Abusix Mail Intelligence blacklist.",
        'flags': ['apikey'],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://abusix.org/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://abusix.com/products/abusix-mail-intelligence/",
                "https://docs.abusix.com/105726-setup-abusix-mail-intelligence/ami%2Fsetup%2Fexample-queries",
                "https://docs.abusix.com/105725-detailed-list-information/ami%2Freturn-codes",
            ],
            'apiKeyInstructions': [
                "Visit https://app.abusix.com/signup",
                "Register a free account",
                "Browse to 'Account Settings' page",
                "The API key is listed on the 'Email protection' page."
            ],
            'logo': "https://abusix.com/wp-content/uploads/2020/10/Footer_logo.png",
            'description': "Abusix Mail Intelligence is an innovative set of blocklists (RBL/DNSBL) "
            "that adds real-time threat data to your existing email protection. "
            "Considered as the first line of defense, blocklists help to prevent email-borne threats "
            "such as spam and malware from entering your network."
        }
    }

    opts = {
        'api_key': "",
        'checkaffiliates': True,
        'checkcohosts': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        'subnetlookup': True,
        'maxsubnet': 24,
        'maxv6subnet': 120,
    }

    optdescs = {
        'api_key': "Abusix Mail Intelligence API key.",
        'checkaffiliates': "Apply checks to affiliates?",
        'checkcohosts': "Apply checks to sites found to be co-hosted on the target's IP?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6netblock': "If looking up owned netblocks, the maximum IPv6 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6subnet': "If looking up subnets, the maximum IPv6 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
    }

    results = None
    errorState = False

    checks = {
        "127.0.0.2": "black",
        "127.0.0.3": "black (composite/heuristic)",
        "127.0.0.4": "exploit / authbl",
        "127.0.0.5": "forged",
        "127.0.0.6": "backscatter",
        "127.0.0.11": "policy (generic rDNS)",
        "127.0.0.12": "policy (missing rDNS)",
        "127.0.0.100": "noip",
        "127.0.1.1": "dblack",
        "127.0.1.2": "dblack (Newly Observed Domain)",
        "127.0.1.3": "dblack (Unshortened)",
        "127.0.2.1": "white",
        "127.0.3.1": "shorthash",
        "127.0.3.2": "diskhash",
        "127.0.4.1": "btc-wallets",
        "127.0.5.1": "attachhash",
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
            'IPV6_ADDRESS',
            'AFFILIATE_IPADDR',
            'AFFILIATE_IPV6_ADDRESS',
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
            'INTERNET_NAME',
            'AFFILIATE_INTERNET_NAME',
            'CO_HOSTED_SITE',
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "BLACKLISTED_INTERNET_NAME",
            "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            "BLACKLISTED_COHOST",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST",
        ]

    def reverseIpAddress(self, ipaddr):
        if not self.sf.validIP(ipaddr):
            self.debug(f"Invalid IPv4 address {ipaddr}")
            return None
        return ipaddress.ip_address(ipaddr).reverse_pointer.replace('.in-addr.arpa', '')

    def reverseIp6Address(self, ipaddr):
        if not self.sf.validIP6(ipaddr):
            self.debug(f"Invalid IPv6 address {ipaddr}")
            return None
        return ipaddress.ip_address(ipaddr).reverse_pointer.replace('.ip6.arpa', '')

    def query(self, qaddr):
        """Query Abusix Mail Intelligence DNS.

        Args:
            qaddr (str): Host name or IPv4 address.

        Returns:
            list: Abusix DNS entries
        """
        if self.sf.validIP(qaddr):
            lookup = f"{self.reverseIpAddress(qaddr)}.{self.opts['api_key']}.combined.mail.abusix.zone"
        elif self.sf.validIP6(qaddr):
            lookup = f"{self.reverseIp6Address(qaddr)}.{self.opts['api_key']}.combined.mail.abusix.zone"
        else:
            lookup = f"{qaddr}.{self.opts['api_key']}.combined.mail.abusix.zone"

        self.debug(f"Checking Abusix Mail Intelligence blacklist: {lookup}")

        try:
            return self.sf.resolveHost(lookup)
        except Exception as e:
            self.debug(f"Abusix Mail Intelligence did not resolve {qaddr} / {lookup}: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if not self.opts['api_key']:
            self.error(f"You enabled {self.__class__.__name__} but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName in ['NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            if not self.opts['subnetlookup']:
                return

            if eventName == 'NETBLOCKV6_MEMBER':
                max_subnet = self.opts['maxv6subnet']
            else:
                max_subnet = self.opts['maxsubnet']

            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        elif eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts['netblocklookup']:
                return

            if eventName == 'NETBLOCKV6_OWNER':
                max_netblock = self.opts['maxv6netblock']
            else:
                max_netblock = self.opts['maxnetblock']

            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
        elif eventName == "INTERNET_NAME":
            malicious_type = "MALICIOUS_INTERNET_NAME"
            blacklist_type = "BLACKLISTED_INTERNET_NAME"
        elif eventName == "AFFILIATE_INTERNET_NAME":
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_INTERNET_NAME"
            blacklist_type = "BLACKLISTED_AFFILIATE_INTERNET_NAME"
        elif eventName == "CO_HOSTED_SITE":
            if not self.opts.get('checkcohosts', False):
                return
            malicious_type = "MALICIOUS_COHOST"
            blacklist_type = "BLACKLISTED_COHOST"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        addrs = list()
        if eventName.startswith("NETBLOCK"):
            for addr in IPNetwork(eventData):
                addrs.append(str(addr))
        else:
            addrs.append(eventData)

        for addr in addrs:
            if self.checkForStop():
                return

            if self.errorState:
                return

            res = self.query(addr)

            self.results[addr] = True

            if not res:
                continue

            self.debug(f"{addr} found in Abusix Mail Intelligence DNS")

            for result in res:
                k = str(result)

                if k not in self.checks:
                    if 'mail.abusix.zone' not in result:
                        # This is an error. The "checks" dict may need to be updated.
                        self.error(f"Abusix Mail Intelligence resolved address {addr} to unknown IP address {result} not found in Abusix Mail Intelligence list.")
                    continue

                text = f"Abusix Mail Intelligence - {self.checks[k]} [{addr}]\n<SFURL>https://lookup.abusix.com/search?q={addr}</SFURL>"

                evt = SpiderFootEvent(blacklist_type, text, self.__name__, event)
                self.notifyListeners(evt)

                evt = SpiderFootEvent(malicious_type, text, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_abusix class
