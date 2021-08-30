# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_spamcop
# Purpose:      SpiderFoot plug-in for looking up whether IPs/Netblocks/Domains
#               appear in the spamcop block lists, indicating potential open-relays,
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


class sfp_spamcop(SpiderFootPlugin):

    meta = {
        'name': "SpamCop",
        'summary': "Query various spamcop databases for open relays, open proxies, vulnerable servers, etc.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.spamcop.net/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.spamcop.net/help.shtml",
                "https://www.spamcop.net/bl.shtml",
                "https://www.spamcop.net/fom-serve/cache/291.html"
            ],
            'favIcon': "https://www.spamcop.net/images/favicon.ico",
            'logo': "https://www.spamcop.net/images/05logo.png",
            'description': "SpamCop is the premier service for reporting spam. "
            "SpamCop determines the origin of unwanted email and reports it "
            "to the relevant Internet service providers.",
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
        "bl.spamcop.net": "SpamCop Blacklist"
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
                return None

            try:
                lookup = self.reverseAddr(qaddr) + "." + domain
                self.sf.debug("Checking Blacklist: " + lookup)
                addrs = self.sf.resolveHost(lookup)
                self.sf.debug("Addresses returned: " + str(addrs))

                if not addrs:
                    continue

                text = None
                for addr in addrs:
                    if type(self.checks[domain]) is str:
                        text = self.checks[domain] + " (" + qaddr + ")"
                        break
                    else:
                        if str(addr) not in list(self.checks[domain].keys()):
                            self.sf.debug("Return code not found in list: " + str(addr))
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
                self.sf.debug("Unable to resolve " + qaddr + " / " + lookup + ": " + str(e))

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return None
        self.results[eventData] = True

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            max_netblock = self.opts['maxnetblock']
            if IPNetwork(eventData).prefixlen < max_netblock:
                self.sf.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return

            max_subnet = self.opts['maxsubnet']
            if IPNetwork(eventData).prefixlen < max_subnet:
                self.sf.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

        if eventName.startswith("NETBLOCK_"):
            for addr in IPNetwork(eventData):
                if self.checkForStop():
                    return
                self.queryAddr(str(addr), parentEvent)
        else:
            self.queryAddr(eventData, parentEvent)

# End of sfp_spamcop class
