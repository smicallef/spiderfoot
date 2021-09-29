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

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_cloudflaredns(SpiderFootPlugin):

    meta = {
        'name': "CloudFlare Malware DNS",
        'summary': "Check if a host would be blocked by CloudFlare Malware-blocking DNS",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.cloudflare.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://developers.cloudflare.com/1.1.1.1/1.1.1.1-for-families/"
            ],
            'favIcon': "https://www.cloudflare.com/img/favicon/favicon-32x32.png",
            'logo': "https://www.cloudflare.com/img/logo-web-badges/cf-logo-on-white-bg.svg",
            'description': "1.1.1.1 for Families is the easiest way to add a layer of protection to "
            "your home network and protect it from malware and adult content. "
            "1.1.1.1 for Families leverages Cloudflare’s global network to ensure "
            "that it is fast and secure around the world.",
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
        res.nameservers = ["1.1.1.2", "1.0.0.2"]

        try:
            addrs = res.resolve(qaddr)
            self.debug(f"Addresses returned: {addrs}")
        except Exception:
            self.debug(f"Unable to resolve {qaddr}")
            return False

        if not addrs:
            return False

        if "0.0.0.0" in self.sf.normalizeDNS(addrs):
            return False

        return True

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event
        resolved = False

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return
        self.results[eventData] = True

        # Check that it resolves first, as it becomes a valid
        # malicious host only if NOT resolved by CloudFlare DNS.
        try:
            if self.sf.resolveHost(eventData) or self.sf.resolveHost6(eventData):
                resolved = True
        except Exception:
            return

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
