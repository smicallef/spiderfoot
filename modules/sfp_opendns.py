# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_opendns
# Purpose:      SpiderFoot plug-in for looking up whether hosts are blocked by
#               OpenDNS DNS (208.67.222.222 and 208.67.220.220)
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     30/05/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import socket
import dns.resolver
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_opendns(SpiderFootPlugin):
    """OpenDNS:Investigate,Passive:Reputation Systems::Check if a host would be blocked by OpenDNS DNS"""

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME", "AFFILIATE_INTERNET_NAME", "CO_HOSTED_SITE"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["MALICIOUS_INTERNET_NAME", "MALICIOUS_AFFILIATE_INTERNET_NAME",
                "MALICIOUS_COHOST", "IP_ADDRESS", "AFFILIATE_IPADDR"]

    def queryAddr(self, qaddr):
        res = dns.resolver.Resolver()
        res.nameservers = [ "208.67.222.222", "208.67.220.220" ]

        try:
            addrs = res.query(qaddr)
            self.sf.debug("Addresses returned: " + str(addrs))
        except BaseException as e:
            self.sf.debug("Unable to resolve " + qaddr)
            return False

        if addrs:
            return True
        return False

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        # Check that it resolves first, as it becomes a valid
        # malicious host only if NOT resolved by OpenDNS.
        try:
            addrs = self.sf.normalizeDNS(socket.gethostbyname_ex(eventData))
        except BaseException as e:
            self.sf.debug("Unable to resolve " + eventData + ": " + str(e))
            return None

        if not addrs:
            self.sf.debug("Unable to resolve " + eventData)
            return None

        for addr in addrs:
            if not self.sf.validIP(addr):
                continue

            if eventName == "INTERNET_NAME":
                evt = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(evt)

            if eventName == "AFFILIATE_INTERNET_NAME":
                evt = SpiderFootEvent("AFFILIATE_IPADDR", addr, self.__name__, event)
                self.notifyListeners(evt)

        # Check if the host is resolved by OpenDNS
        found = self.queryAddr(eventData)

        if found:
            return None

        if eventName == "CO_HOSTED_SITE":
            typ = "MALICIOUS_COHOST"
        else:
            typ = "MALICIOUS_" + eventName

        evt = SpiderFootEvent(typ, "Blocked by OpenDNS [" + eventData + "]",
                              self.__name__, parentEvent)
        self.notifyListeners(evt)

# End of sfp_opendns class
