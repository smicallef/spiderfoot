# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_yandexdns
# Purpose:      SpiderFoot plug-in for looking up whether hosts are blocked by
#               Yandex DNS.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     30/05/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import dns.resolver

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_yandexdns(SpiderFootPlugin):

    meta = {
        'name': "Yandex DNS",
        'summary': "Check if a host would be blocked by Yandex DNS.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://yandex.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://tech.yandex.com/",
                "https://dns.yandex.com/advanced/",
            ],
            'favIcon': "https://yastatic.net/iconostasis/_/tToKamh-mh5XlViKpgiJRQgjz1Q.png",
            'logo': "https://yastatic.net/iconostasis/_/tToKamh-mh5XlViKpgiJRQgjz1Q.png",
            'description': "Yandex.DNS is a free, recursive DNS service. "
            "Yandex.DNS' servers are located in Russia, CIS countries, and Western Europe."
            'In "Basic" mode, there is no traffic filtering. '
            'In "Safe" mode, protection from infected and fraudulent sites is provided. '
            '"Family" mode enables protection from dangerous sites and blocks sites with adult content.'
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None

    checks = {
        "213.180.193.250": "Yandex - Infected",
        "93.158.134.250": "Yandex - Adult",
    }

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
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST",
        ]

    # Query Yandex DNS "family" servers
    def queryAddr(self, qaddr):
        if not qaddr:
            return None

        res = dns.resolver.Resolver()
        res.nameservers = ["77.88.8.7", "77.88.8.3"]

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
            malicious_type = "MALICIOUS_INTERNET_NAME"
            blacklist_type = "BLACKLISTED_INTERNET_NAME"
        elif eventName == "AFFILIATE_INTERNET_NAME":
            malicious_type = "MALICIOUS_AFFILIATE_INTERNET_NAME"
            blacklist_type = "BLACKLISTED_AFFILIATE_INTERNET_NAME"
        elif eventName == "CO_HOSTED_SITE":
            malicious_type = "MALICIOUS_COHOST"
            blacklist_type = "BLACKLISTED_COHOST"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")

        res = self.queryAddr(eventData)

        if not res:
            return

        self.debug(f"{eventData} found in Yandex Blocklist: {res}")

        for result in res:
            k = str(result)
            if k not in self.checks:
                continue

            evt = SpiderFootEvent(blacklist_type, f"{self.checks[k]} [{eventData}]", self.__name__, event)
            self.notifyListeners(evt)

            if k == '213.180.193.250':
                evt = SpiderFootEvent(malicious_type, f"{self.checks[k]} [{eventData}]", self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_yandexdns class
