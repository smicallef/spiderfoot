# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_cleanbrowsing
# Purpose:      SpiderFoot plug-in for looking up whether hosts are blocked by
#               Cleanbrowsing.org DNS (185.228.168.168 and 185.228.168.169)
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     30/05/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import dns.resolver
from sflib import SpiderFootPlugin, SpiderFootEvent


class sfp_cleanbrowsing(SpiderFootPlugin):
    """Cleanbrowsing.org:Investigate,Passive:Reputation Systems::Check if a host would be blocked by Cleanbrowsing.org DNS"""

    meta = {
        'name': "Cleanbrowsing.org",
        'summary': "Check if a host would be blocked by Cleanbrowsing.org DNS",
        'flags': [""],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://cleanbrowsing.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://cleanbrowsing.org/guides/",
                "https://cleanbrowsing.org/how-it-works",
                "https://cleanbrowsing.org/web-filtering-for-shools-and-cipa-compliance",
                "https://cleanbrowsing.org/getting-started"
            ],
            'favIcon': "https://cleanbrowsing.org/favicon-new.ico",
            'logo': "https://cleanbrowsing.org/images/logos/CleanBrowsing-logo-large-2019-Orange-II.png",
            'description': "You get to decide what type of content is allowed in your home or network via our "
                                "DNS-based content filtering service. Parents can protect their kids from adult content, "
                                "schools can be CIPA compliant and businesses can block malicious domains and "
                                "gain visibility into their network.\n"
                                "CleanBrowsing is a DNS-based content filtering service that offers a safe way to browse the web without surprises. "
                                "It intercepts domain requests and filter sites that should be blocked, based on your requirements. "
                                "Our free family filter, for example, blocks adult content, while still allowing Google, "
                                "Youtube, Bing, DuckDuckGo and the rest of the web to load safely.",
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
        res.nameservers = ["185.228.168.168", "185.228.168.169"]

        try:
            addrs = res.query(qaddr)
            self.sf.debug("Addresses returned: " + str(addrs))
        except BaseException:
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
            return None
        self.results[eventData] = True

        # Check that it resolves first, as it becomes a valid
        # malicious host only if NOT resolved by Cleanbrowsing.org.
        try:
            if self.sf.resolveHost(eventData):
                resolved = True
        except BaseException:
            return None

        if resolved:
            found = self.queryAddr(eventData)
            typ = "MALICIOUS_" + eventName
            if eventName == "CO_HOSTED_SITE":
                typ = "MALICIOUS_COHOST"
            if not found:
                evt = SpiderFootEvent(typ, "Blocked by Cleanbrowsing.org [" + eventData + "]",
                                      self.__name__, parentEvent)
                self.notifyListeners(evt)

# End of sfp_cleanbrowsing class
