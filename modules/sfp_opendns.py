# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_opendns
# Purpose:      SpiderFoot plug-in for looking up whether hosts are blocked by
#               OpenDNS.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     30/05/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import dns.resolver

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_opendns(SpiderFootPlugin):

    meta = {
        'name': "OpenDNS",
        'summary': "Check if a host would be blocked by OpenDNS.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.opendns.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://support.opendns.com/hc/en-us/categories/204012807-OpenDNS-Knowledge-Base",
                "https://support.opendns.com/hc/en-us/categories/204012907-OpenDNS-Device-Configuration"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://www.opendns.com/",
            'logo': "https://d15ni2z53ptwz9.cloudfront.net/opendns-www/img/logo-opendns.png",
            'description': "Cisco Umbrella provides protection against threats on the internet such as "
            "malware, phishing, and ransomware.\n"
            "OpenDNS is a suite of consumer products aimed at "
            "making your internet faster, safer, and more reliable.",
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
            "MALICIOUS_COHOST"]

    def queryAddr(self, qaddr):
        res = dns.resolver.Resolver()
        res.nameservers = ["208.67.222.222", "208.67.220.220"]
        # FamilyShield
        # res.nameservers = ["208.67.222.123", "208.67.220.123"]

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
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        # Check that it resolves first, as it becomes a valid
        # malicious host only if NOT resolved by OpenDNS.
        if not self.sf.resolveHost(eventData) and not self.sf.resolveHost6(eventData):
            return

        found = self.queryAddr(eventData)

        # Host was found, not blocked
        if found:
            return

        self.debug(f"{eventData} was blocked by OpenDNS")

        typ = "MALICIOUS_" + eventName

        if eventName == "CO_HOSTED_SITE":
            typ = "MALICIOUS_COHOST"

        evt = SpiderFootEvent(
            typ,
            f"Blocked by OpenDNS [{eventData}]",
            self.__name__,
            event
        )
        self.notifyListeners(evt)

# End of sfp_opendns class
