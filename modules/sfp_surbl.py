# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_surbl
# Purpose:     SpiderFoot plug-in to check whether IP addresses, netblocks, and
#              domains appear in the SURBL blacklist.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-10-17
# Copyright:   (c) bcoles 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_surbl(SpiderFootPlugin):

    meta = {
        'name': "SURBL",
        'summary': "Check if a netblock, IP address or domain is in the SURBL blacklist.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://www.surbl.org/",
            'model': "FREE_NOAUTH_UNLIMITED",  # 250,000 messages per day
            'references': [
                "http://www.surbl.org/lists",
                "http://www.surbl.org/guidelines",
            ],
            'logo': "http://www.surbl.org/images/logo.png",
            'description': "SURBLs are lists of web sites that have appeared in unsolicited messages. "
            "Unlike most lists, SURBLs are not lists of message senders."
        }
    }

    opts = {
        'checkaffiliates': True,
        'checkcohosts': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
        'checkcohosts': "Apply checks to sites found to be co-hosted on the target's IP?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
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
            'IP_ADDRESS',
            'AFFILIATE_IPADDR',
            'NETBLOCK_OWNER',
            'NETBLOCK_MEMBER',
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

    # Swap 1.2.3.4 to 4.3.2.1
    def reverseAddr(self, ipaddr):
        if not self.sf.validIP(ipaddr):
            self.debug(f"Invalid IPv4 address {ipaddr}")
            return None
        return '.'.join(reversed(ipaddr.split('.')))

    def query(self, qaddr):
        """Query SURBL DNS.

        Args:
            qaddr (str): Host name or IPv4 address.

        Returns:
            list: SURBL DNS entries
        """
        if self.sf.validIP(qaddr):
            lookup = self.reverseAddr(qaddr) + '.multi.surbl.org'
        else:
            lookup = f"{qaddr}.multi.surbl.org"

        self.debug(f"Checking SURBL blacklist: {lookup}")

        try:
            return self.sf.resolveHost(lookup)
        except Exception as e:
            self.debug(f"SURBL did not resolve {qaddr} / {lookup}: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventName == "AFFILIATE_IPADDR":
            if not self.opts.get('checkaffiliates', False):
                return
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
        if eventName.startswith("NETBLOCK_"):
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

            self.debug(f"{addr} found in SURBL DNS")

            for result in res:
                k = str(result)

                if not k.startswith('127.0.0.'):
                    continue

                if k == '127.0.0.1':
                    self.error('SURBL rejected lookup request.')
                    self.errorState = True
                    continue

                evt = SpiderFootEvent(blacklist_type, f"SURBL [{addr}]", self.__name__, event)
                self.notifyListeners(evt)

                evt = SpiderFootEvent(malicious_type, f"SURBL [{addr}]", self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_surbl class
