# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_adguard_dns
# Purpose:     SpiderFoot plug-in for looking up whether hosts are blocked by
#              AdGuard DNS servers.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-10-11
# Copyright:   (c) bcoles 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import dns.resolver

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_adguard_dns(SpiderFootPlugin):

    meta = {
        'name': "AdGuard DNS",
        'summary': "Check if a host would be blocked by AdGuard DNS.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://adguard.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://adguard.com/en/adguard-dns/overview.html",
            ],
            'favIcon': "https://adguard.com/img/favicons/favicon.ico",
            'logo': "https://adguard.com/img/favicons/apple-touch-icon.png",
            'description': "AdGuard DNS is a foolproof way to block Internet ads that does not require installing any applications. "
            "It is easy to use, absolutely free, easily set up on any device, and provides you with minimal necessary functions "
            "to block ads, counters, malicious websites, and adult content."
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
            "BLACKLISTED_INTERNET_NAME",
            "BLACKLISTED_AFFILIATE_INTERNET_NAME",
            "BLACKLISTED_COHOST",
        ]

    def queryDefaultDNS(self, qaddr):
        res = dns.resolver.Resolver()
        res.nameservers = ["94.140.14.14", "94.140.15.15"]

        try:
            return res.resolve(qaddr)
        except Exception:
            self.debug(f"Unable to resolve {qaddr}")

        return None

    def queryFamilyDNS(self, qaddr):
        res = dns.resolver.Resolver()
        res.nameservers = ["94.140.14.15", "94.140.15.16"]

        try:
            return res.resolve(qaddr)
        except Exception:
            self.debug(f"Unable to resolve {qaddr}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        if eventName == "INTERNET_NAME":
            blacklist_type = "BLACKLISTED_INTERNET_NAME"
        elif eventName == "AFFILIATE_INTERNET_NAME":
            blacklist_type = "BLACKLISTED_AFFILIATE_INTERNET_NAME"
        elif eventName == "CO_HOSTED_SITE":
            blacklist_type = "BLACKLISTED_COHOST"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        family = self.sf.normalizeDNS(self.queryFamilyDNS(eventData))
        default = self.sf.normalizeDNS(self.queryDefaultDNS(eventData))

        if not family or not default:
            return

        if '94.140.14.35' in family:
            self.debug(f"{eventData} blocked by AdGuard Family DNS")
            evt = SpiderFootEvent(blacklist_type, f"AdGuard - Family Filter [{eventData}]", self.__name__, event)
            self.notifyListeners(evt)

        if '94.140.14.35' in default:
            self.debug(f"{eventData} blocked by AdGuard Default DNS")
            evt = SpiderFootEvent(blacklist_type, f"AdGuard - Default Filter [{eventData}]", self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_adguard_dns class
