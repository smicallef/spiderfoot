# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_comodo
# Purpose:      SpiderFoot plug-in for looking up whether hosts are blocked by
#               Comodo DNS (8.26.56.26 and 8.20.247.20)
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     30/05/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import dns.resolver

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_comodo(SpiderFootPlugin):

    meta = {
        'name': "Comodo",
        'summary': "Check if a host would be blocked by Comodo DNS",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.comodo.com/secure-dns/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://cdome.comodo.com/pdf/Datasheet-Dome-Shield.pdf?af=7639#_ga=2.9039612.872056824.1587327669-445877257.1587327669",
                "https://wiki.comodo.com/frontend/web/category/dome-shield?af=7639#_ga=2.9039612.872056824.1587327669-445877257.1587327669",
                "https://www.comodo.com/secure-dns/secure-dns-assets/dowloads/ccs-dome-shield-whitepaper-threat-intelligence.pdf?af=7639",
                "https://www.comodo.com/secure-dns/secure-dns-assets/dowloads/domeshield-all-use-cases.pdf?af=7639"
            ],
            'favIcon': "https://www.comodo.com/favicon.ico",
            'logo': "https://www.comodo.com/new-assets/images/logo.png",
            'description': "100% cloud-based, load-balanced, geo-distributed, highly available Anycast DNS infrastructure hosted in 25+ countries.\n"
            "Cloud-based web security delivered at the DNS level, first layer for everything internet connected.\n"
            "Per company, location, endpoint, mobile device, IP, subnet and user.\n"
            "Get real-time web visibility for everything internet connected and schedule reports to be sent to your email.",
        }
    }

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
        res.nameservers = ["8.26.56.26", "8.20.247.20"]

        try:
            addrs = res.resolve(qaddr)
            self.sf.debug("Addresses returned: " + str(addrs))
        except Exception:
            self.sf.debug(f"Unable to resolve {qaddr}")
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

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return
        self.results[eventData] = True

        # Check that it resolves first, as it becomes a valid
        # malicious host only if NOT resolved by Comodo.
        try:
            if self.sf.resolveHost(eventData):
                resolved = True
        except Exception:
            return

        if resolved:
            found = self.queryAddr(eventData)
            typ = "MALICIOUS_" + eventName
            if eventName == "CO_HOSTED_SITE":
                typ = "MALICIOUS_COHOST"
            if not found:
                evt = SpiderFootEvent(typ, "Blocked by Comodo DNS [" + eventData + "]",
                                      self.__name__, parentEvent)
                self.notifyListeners(evt)

# End of sfp_comodo class
