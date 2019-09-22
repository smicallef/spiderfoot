# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_norton
# Purpose:      SpiderFoot plug-in for looking up whether hosts are blocked by
#               Norton DNS (199.85.126.20 and 199.85.127.20)
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     30/05/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import socket
import dns.resolver
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_norton(SpiderFootPlugin):
    """Norton ConnectSafe:Investigate,Passive:Reputation Systems::Check if a host would be blocked by Norton ConnectSafe DNS"""

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
                "MALICIOUS_COHOST"]

    def queryAddr(self, qaddr):
        res = dns.resolver.Resolver()
        res.nameservers = [ "199.85.126.20", "199.85.127.20" ]

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
        resolved = False

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            return None
        self.results[eventData] = True

        # Check that it resolves first, as it becomes a valid
        # malicious host only if NOT resolved by Norton.
        try:
            if self.sf.normalizeDNS(socket.gethostbyname_ex(eventData)):
                resolved = True
        except BaseException as e:
            return None

        if resolved:
            found = self.queryAddr(eventData)
            typ = "MALICIOUS_" + eventName
            if eventName == "CO_HOSTED_SITE":
                typ = "MALICIOUS_COHOST"
            if not found:
                evt = SpiderFootEvent(typ, "Blocked by Norton ConnectSafe [" + eventData + "]",
                                      self.__name__, parentEvent)
                self.notifyListeners(evt)

# End of sfp_norton class
