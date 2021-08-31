# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_quad9
# Purpose:      SpiderFoot plug-in for looking up whether hosts are blocked by
#               Quad 9 (9.9.9.9)
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     04/02/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import dns.resolver

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_quad9(SpiderFootPlugin):

    meta = {
        'name': "Quad9",
        'summary': "Check if a host would be blocked by Quad9",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://quad9.net/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.quad9.net/faq/",
                "https://www.quad9.net/#Setup_Quad9"
            ],
            'favIcon': "https://quad9.net/wp-content/uploads/2018/01/favicon-32.png",
            'logo': "https://quad9.net/wp-content/uploads/2017/11/quad9-logo-white@2x.png",
            'description': "Quad9 brings together cyber threat intelligence about malicious domains "
            "from a variety of public and private sources and blocks access "
            "to those malicious domains when your system attempts to contact them.\n"
            "When you use Quad9, attackers and malware cannot leverage the known malicious domains to control your systems, "
            "and their ability to steal your data or cause harm will be hindered. "
            "Quad9 is an effective and easy way to add an additional layer of security to your infrastructure for free.",
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
        return ["INTERNET_NAME", "AFFILIATE_INTERNET_NAME", "CO_HOSTED_SITE"]

    def producedEvents(self):
        return [
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST"]

    def query(self, qry):
        res = dns.resolver.Resolver()
        res.nameservers = ["9.9.9.9"]

        try:
            addrs = res.resolve(qry)
            self.sf.debug(f"Addresses returned: {addrs}")
        except Exception:
            self.sf.debug(f"Unable to resolve {qry}")
            return False

        if addrs:
            return True
        return False

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        # Check that it resolves first, as it becomes a valid
        # malicious host only if NOT resolved by Quad9.
        if not self.sf.resolveHost(eventData):
            return

        found = self.query(eventData)

        # Host was found, not blocked
        if found:
            return

        typ = "MALICIOUS_" + eventName

        if eventName == "CO_HOSTED_SITE":
            typ = "MALICIOUS_COHOST"

        evt = SpiderFootEvent(
            typ,
            f"Blocked by Quad9 [{eventData}]\n<SFURL>https://quad9.net/result/?url={eventData}</SFURL>",
            self.__name__, parentEvent
        )
        self.notifyListeners(evt)

# End of sfp_quad9 class
