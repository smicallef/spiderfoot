# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_honeypot
# Purpose:      SpiderFoot plug-in for looking up whether IPs appear in the
#               projecthoneypot.org database.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     16/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import socket
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_honeypot(SpiderFootPlugin):
    """Honeypot Checker:Investigate,Passive:Reputation Systems:apikey:Query the projecthoneypot.org database for entries."""


    # Default options
    opts = {
        'api_key': "",
        'searchengine': False,
        'threatscore': 0,
        'timelimit': 30,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
    }

    # Option descriptions
    optdescs = {
        'api_key': "The API key you obtained from projecthoneypot.org",
        'searchengine': "Include entries considered search engines?",
        'threatscore': "Threat score minimum, 0 being everything and 255 being only the most serious.",
        'timelimit': "Maximum days old an entry can be. 255 is the maximum, 0 means you'll get nothing.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    results = dict()
    errorState = False

    # Status codes according to:
    # http://www.projecthoneypot.org/httpbl_api.php
    statuses = {
        "0": "Search Engine",
        "1": "Suspicious",
        "2": "Harvester",
        "3": "Suspicious & Harvester",
        "4": "Comment Spammer",
        "5": "Suspicious & Comment Spammer",
        "6": "Harvester & Comment Spammer",
        "7": "Suspicious & Harvester & Comment Spammer",
        "8": "Unknown (8)",
        "9": "Unknown (9)",
        "10": "Unknown (10)"
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

    # Returns text about the IP status returned from DNS
    def reportIP(self, addr):
        bits = addr.split(".")
        if int(bits[1]) > self.opts['timelimit']:
            return None

        if int(bits[2]) < self.opts['threatscore']:
            return None

        if int(bits[3]) == 0 and self.opts['searchengine']:
            return None

        text = "Honeypotproject ({0}): " + self.statuses[bits[3]] + \
               "\nLast Activity: " + bits[1] + " days ago" + \
               "\nThreat Level: " + bits[2]
        return text

    def queryAddr(self, qaddr, parentEvent):
        eventName = parentEvent.eventType

        try:
            lookup = self.opts['api_key'] + "." + \
                     self.reverseAddr(qaddr) + ".dnsbl.httpbl.org"

            self.sf.debug("Checking Honeypot: " + lookup)
            addrs = self.sf.normalizeDNS(socket.gethostbyname_ex(lookup))
            self.sf.debug("Addresses returned: " + str(addrs))

            text = None
            for addr in addrs:
                text = self.reportIP(addr)
                if text is None:
                    continue
                else:
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

                evt = SpiderFootEvent(e, text.format(qaddr), self.__name__, parentEvent)
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

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_honeypot but did not set an API key!", False)
            self.errorState = True
            return None

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

# End of sfp_honeypot class
