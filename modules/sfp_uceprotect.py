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
        'summary': "Query the UCEPROTECT databases for open relays, open proxies, vulnerable servers, etc.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "http://www.uceprotect.net/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "http://www.uceprotect.net/en/index.php?m=6&s=0",
                "http://www.uceprotect.net/en/index.php?m=13&s=0",
                "http://www.uceprotect.net/en/rblcheck.php"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=http://www.uceprotect.net/",
            'logo': "http://www.uceprotect.net/en/logo.gif",
            'description': "UCE Protect is a DNS Blacklisting service whose mission is to stop mail abuse globally.",
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
        "dnsbl-1.uceprotect.net": 'UCEPROTECT - Level 1 (high likelihood)',
        "dnsbl-2.uceprotect.net": 'UCEPROTECT - Level 2 (some false positives)'
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
                self.debug("Addresses returned: " + str(addrs))

                if not addrs:
                    continue

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
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                    self.debug("Network size bigger than permitted: "
                               + str(IPNetwork(eventData).prefixlen) + " > "
                               + str(self.opts['maxnetblock']))
                    return

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxsubnet']:
                    self.debug("Network size bigger than permitted: "
                               + str(IPNetwork(eventData).prefixlen) + " > "
                               + str(self.opts['maxsubnet']))
                    return

        if eventName.startswith("NETBLOCK_"):
            for addr in IPNetwork(eventData):
                if self.checkForStop():
                    return
                self.queryAddr(str(addr), parentEvent)
        else:
            self.queryAddr(eventData, parentEvent)

# End of sfp_uceprotect class
