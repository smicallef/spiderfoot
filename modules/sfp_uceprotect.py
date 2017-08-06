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

import socket
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_uceprotect(SpiderFootPlugin):
    """UCEPROTECT:Investigate,Passive:Reputation Systems::Query the UCEPROTECT databases for open relays, open proxies, vulnerable servers, etc."""


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
    results = dict()

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
        self.results = dict()

        for opt in userOpts.keys():
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
                addrs = self.sf.normalizeDNS(socket.gethostbyname_ex(lookup))
                self.sf.debug("Addresses returned: " + str(addrs))

                text = None
                for addr in addrs:
                    if type(self.checks[domain]) is str:
                        text = self.checks[domain] + " (" + qaddr + ")"
                        break
                    else:
                        if str(addr) not in self.checks[domain].keys():
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

            except BaseException as e:
                self.sf.debug("Unable to resolve " + qaddr + " / " + lookup + ": " + str(e))

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event
        addrlist = list()

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            return None
        self.results[eventData] = True

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return None
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                    self.sf.debug("Network size bigger than permitted: " +
                                  str(IPNetwork(eventData).prefixlen) + " > " +
                                  str(self.opts['maxnetblock']))
                    return None

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return None
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxsubnet']:
                    self.sf.debug("Network size bigger than permitted: " +
                                  str(IPNetwork(eventData).prefixlen) + " > " +
                                  str(self.opts['maxsubnet']))
                    return None

        if eventName.startswith("NETBLOCK_"):
            for addr in IPNetwork(eventData):
                if self.checkForStop():
                    return None
                self.queryAddr(str(addr), parentEvent)
        else:
            self.queryAddr(eventData, parentEvent)

# End of sfp_uceprotect class
