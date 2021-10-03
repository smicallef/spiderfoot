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

    # Target
    results = None

    # Whole bunch here:
    # http://en.wikipedia.org/wiki/Comparison_of_DNS_blacklists
    # Check out:
    # http://www.blocklist.de/en/rbldns.html
    checks = {
        "http.dnsbl.sorbs.net": "SORBS - Open HTTP Proxy",
        "socks.dnsbl.sorbs.net": "SORBS - Open SOCKS Proxy",
        "misc.dnsbl.sorbs.net": "SORBS - Open Proxy",
        "smtp.dnsbl.sorbs.net": "SORBS - Open SMTP Relay",
        "spam.dnsbl.sorbs.net": "SORBS - Spammer",
        "recent.spam.dnsbl.sorbs.net": "SORBS - Recent Spammer",
        "web.dnsbl.sorbs.net": "SORBS - Vulnerability exposed to spammers"
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'AFFILIATE_IPADDR', 'NETBLOCK_OWNER',
                'NETBLOCK_MEMBER']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["BLACKLISTED_IPADDR", "BLACKLISTED_AFFILIATE_IPADDR",
                "BLACKLISTED_SUBNET", "BLACKLISTED_NETBLOCK"]

    # Swap 1.2.3.4 to 4.3.2.1
    def reverseAddr(self, ipaddr):
        return '.'.join(reversed(ipaddr.split('.')))

    def queryAddr(self, qaddr, parentEvent):
        eventName = parentEvent.eventType

        for domain in self.checks:
            if self.checkForStop():
                return

            try:
                lookup = self.reverseAddr(qaddr) + "." + domain
                self.debug("Checking Blacklist: " + lookup)
                addrs = self.sf.resolveHost(lookup)
                if not addrs:
                    continue

                self.debug("Addresses returned: " + str(addrs))

                text = None
                for addr in addrs:
                    if type(self.checks[domain]) is str:
                        text = self.checks[domain] + " (" + qaddr + ")"
                        break
                    else:
                        if str(addr) not in list(self.checks[domain].keys()):
                            self.debug("Return code not found in list: " + str(addr))
                            continue

                        k = str(addr)
                        text = self.checks[domain][k] + " (" + qaddr + ")"
                        break

                if text is not None:
                    if eventName == "AFFILIATE_IPADDR":
                        e = "BLACKLISTED_AFFILIATE_IPADDR"
                    if eventName == "IP_ADDRESS":
                        e = "BLACKLISTED_IPADDR"
                    if eventName == "NETBLOCK_OWNER":
                        e = "BLACKLISTED_NETBLOCK"
                    if eventName == "NETBLOCK_MEMBER":
                        e = "BLACKLISTED_SUBNET"

                    evt = SpiderFootEvent(e, text, self.__name__, parentEvent)
                    self.notifyListeners(evt)

            except Exception as e:
                self.debug("Unable to resolve " + qaddr + " / " + lookup + ": " + str(e))

        return

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

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

        if eventName.startswith("NETBLOCK_"):
            for addr in IPNetwork(eventData):
                if self.checkForStop():
                    return
                self.queryAddr(str(addr), parentEvent)
        else:
            self.queryAddr(eventData, parentEvent)

# End of sfp_sorbs class
