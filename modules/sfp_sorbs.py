# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_sorbs
# Purpose:      SpiderFoot plug-in for looking up whether IPs/Netblocks/Domains
#               appear in the SORBS blocklist, indicating potential open-relays,
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


class sfp_sorbs(SpiderFootPlugin):

    meta = {
        'name': "SORBS",
        'summary': "Query the SORBS database for open relays, open proxies, vulnerable servers, etc.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://www.sorbs.net/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "http://www.sorbs.net/information/proxy.shtml",
                "http://www.sorbs.net/information/spamfo/",
                "http://www.sorbs.net/general/using.shtml"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=http://www.sorbs.net/",
            'logo': "http://www.sorbs.net/img/pix.gif",
            'description': "The Spam and Open Relay Blocking System (SORBS) was conceived as an anti-spam project "
            "where a daemon would check \"on-the-fly\", all servers from which it received email "
            "to determine if that email was sent via various types of proxy and open-relay servers.\n"
            "The SORBS (Spam and Open Relay Blocking System) provides free access to its "
            "DNS-based Block List (DNSBL) to effectively block email from more than 12 million host servers "
            "known to disseminate spam, phishing attacks and other forms of malicious email.",
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

    # Zones:
    # "http.dnsbl.sorbs.net": "127.0.0.2",
    # "socks.dnsbl.sorbs.net": "127.0.0.3",
    # "misc.dnsbl.sorbs.net": "127.0.0.4",
    # "smtp.dnsbl.sorbs.net": "127.0.0.5",
    # "new.spam.dnsbl.sorbs.net": "127.0.0.6",
    # "recent.spam.dnsbl.sorbs.net": "127.0.0.6",
    # "old.spam.dnsbl.sorbs.net": "127.0.0.6",
    # "spam.dnsbl.sorbs.net": "127.0.0.6",
    # "escalations.dnsbl.sorbs.net": "127.0.0.6",
    # "web.dnsbl.sorbs.net": "127.0.0.7",
    # "block.dnsbl.sorbs.net": "127.0.0.8",
    # "zombie.dnsbl.sorbs.net": "127.0.0.9",
    # "dul.dnsbl.sorbs.net": "127.0.0.10",
    # "badconf.rhsbl.sorbs.net": "127.0.0.11",
    # "nomail.rhsbl.sorbs.net": "127.0.0.12",
    # "noserver.dnsbl.sorbs.net": "127.0.0.14",

    checks = {
        "127.0.0.2": "SORBS - Open HTTP Proxy",
        "127.0.0.3": "SORBS - Open SOCKS Proxy",
        "127.0.0.4": "SORBS - Open Proxy",
        "127.0.0.5": "SORBS - Open SMTP Relay",
        "127.0.0.6": "SORBS - Spammer",
        "127.0.0.7": "SORBS - Vulnerability exposed to spammers",
        "127.0.0.8": "SORBS - Host ignored by SORBS",
        "127.0.0.9": "SORBS - Hijacked host",
        "127.0.0.10": "SORBS - Dynamic IP address range",
        "127.0.0.11": "SORBS - Misconfigured A or MX record",
        "127.0.0.12": "SORBS - Host does not send mail",
        "127.0.0.14": "SORBS - Network does not contain servers",
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
            "PROXY_HOST"
        ]

    # Swap 1.2.3.4 to 4.3.2.1
    def reverseAddr(self, ipaddr):
        if not self.sf.validIP(ipaddr):
            self.debug(f"Invalid IPv4 address {ipaddr}")
            return None
        return '.'.join(reversed(ipaddr.split('.')))

    def queryAddr(self, qaddr):
        """Query SORBS DNS for an IPv4 address.

        Args:
            qaddr (str): IPv4 address.

        Returns:
            list: SORBS DNS entries
        """
        if not self.sf.validIP(qaddr):
            self.debug(f"Invalid IPv4 address {qaddr}")
            return None

        try:
            lookup = self.reverseAddr(qaddr) + '.dnsbl.sorbs.net'
            self.debug(f"Checking SORBS blacklist: {lookup}")
            return self.sf.resolveHost(lookup)
        except Exception as e:
            self.debug(f"SORBS did not resolve {qaddr} / {lookup}: {e}")

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

            self.debug(f"{addr} found in SORBS DNS")

            for result in res:
                k = str(result)
                if k not in self.checks:
                    if not result.endswith('.dnsbl.sorbs.net'):
                        # This is an error. The "checks" dict may need to be updated.
                        self.error(f"SORBS resolved address {addr} to unknown IP address {result} not found in SORBS list.")
                    continue

                evt = SpiderFootEvent(blacklist_type, f"{self.checks[k]} [{addr}]", self.__name__, event)
                self.notifyListeners(evt)

                if k in [
                    "127.0.0.2",
                    "127.0.0.3",
                    "127.0.0.4",
                ]:
                    evt = SpiderFootEvent("PROXY_HOST", eventData, self.__name__, event)
                    self.notifyListeners(evt)

                if k not in [
                    "127.0.0.8",
                    "127.0.0.10",
                    "127.0.0.11",
                    "127.0.0.12",
                    "127.0.0.14",
                ]:
                    evt = SpiderFootEvent(malicious_type, f"{self.checks[k]} [{addr}]", self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_sorbs class
