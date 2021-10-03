# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_cleanbrowsing
# Purpose:     SpiderFoot plug-in for looking up whether hosts are blocked by
#              CleanBrowsing.org DNS (185.228.168.168 and 185.228.168.169)
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     30/05/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import dns.resolver

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_cleanbrowsing(SpiderFootPlugin):

    meta = {
        'name': "CleanBrowsing.org",
        'summary': "Check if a host would be blocked by CleanBrowsing.org DNS",
        'flags': [],
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

    opts = {
    }

    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME",
            "CO_HOSTED_SITE"
        ]

    def producedEvents(self):
        return [
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST"
        ]

    def queryAddr(self, qaddr):
        res = dns.resolver.Resolver()
        res.nameservers = ["185.228.168.168", "185.228.168.169"]

        try:
            addrs = res.resolve(qaddr)
            self.debug(f"Addresses returned: {addrs}")
        except Exception:
            self.debug(f"Unable to resolve {qaddr}")
            return False

        if addrs:
            return True
        return False

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        # Check that it resolves first, as it becomes a valid
        # malicious host only if NOT resolved by CleanBrowsing.org.
        if not self.sf.resolveHost(eventData) and not self.sf.resolveHost6(eventData):
            return

        found = self.queryAddr(eventData)

        # Host was found, not blocked
        if found:
            return

        typ = "MALICIOUS_" + eventName

        if eventName == "CO_HOSTED_SITE":
            typ = "MALICIOUS_COHOST"

        evt = SpiderFootEvent(
            typ,
            f"Blocked by CleanBrowsing.org [{eventData}]",
            self.__name__,
            parentEvent
        )
        self.notifyListeners(evt)

# End of sfp_cleanbrowsing class
