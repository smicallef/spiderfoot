# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_cloudflaredns
# Purpose:      SpiderFoot plug-in for looking up whether hosts are blocked by
#               CloudFlare malware DNS (1.1.1.2).
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     11/05/2020
# Copyright:   (c) Steve Micallef 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import dns.resolver
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_cloudflaredns(SpiderFootPlugin):
    """CloudFlare Malware DNS:Investigate,Passive:Reputation Systems::Check if a host would be blocked by CloudFlare Malware-blocking DNS"""

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
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
        res.nameservers = [ "1.1.1.2", "1.0.0.2" ]

        try:
            addrs = res.query(qaddr)
            self.sf.debug("Addresses returned: " + str(addrs))
        except BaseException as e:
            self.sf.debug("Unable to resolve " + qaddr)
            return False

        if addrs:
            a = self.sf.normalizeDNS(addrs)
            if "0.0.0.0" in a:
                return False
            else:
                return True

        return False

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event
        resolved = False

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if eventData in self.results:
            return None
        self.results[eventData] = True

        # Check that it resolves first, as it becomes a valid
        # malicious host only if NOT resolved by CloudFlare DNS.
        try:
            if self.sf.resolveHost(eventData):
                resolved = True
        except BaseException as e:
            return None

        if resolved:
            found = self.queryAddr(eventData)
            typ = "MALICIOUS_" + eventName
            if eventName == "CO_HOSTED_SITE":
                typ = "MALICIOUS_COHOST"
            if not found:
                evt = SpiderFootEvent(typ, "Blocked by CloudFlare DNS [" + eventData + "]",
                                      self.__name__, parentEvent)
                self.notifyListeners(evt)

# End of sfp_cloudflaredns class
