# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_yandexdns
# Purpose:      SpiderFoot plug-in for looking up whether hosts are blocked by
#               Yandex DNS (77.88.8.88 and 77.88.8.2)
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


class sfp_yandexdns(SpiderFootPlugin):
    """Yandex DNS:Investigate,Passive:Reputation Systems::Check if a host would be blocked by Yandex DNS"""

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

    # Query Yandex DNS "safe" servers
    # https://dns.yandex.com/advanced/
    def queryAddr(self, qaddr):
        res = dns.resolver.Resolver()
        res.nameservers = [ "77.88.8.88", "77.88.8.2" ]

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
        # malicious host only if NOT resolved by Yandex.
        try:
            if self.sf.normalizeDNS(socket.gethostbyname_ex(eventData)):
                resolved = True
        except BaseException as e:
            self.sf.debug("Unable to resolve " + eventData)
            return None

        if not resolved:
            return None

        found = self.queryAddr(eventData)

        if not found:
            return None

        if eventName == "CO_HOSTED_SITE":
            typ = "MALICIOUS_COHOST"
        else:
            typ = "MALICIOUS_" + eventName

        evt = SpiderFootEvent(typ, "Blocked by Yandex [" + eventData + "]",
                              self.__name__, parentEvent)
        self.notifyListeners(evt)

# End of sfp_yandexdns class
