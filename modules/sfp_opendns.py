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
                "https://www.opendns.com/setupguide/?url=familyshield",
                "https://support.opendns.com/hc/en-us/categories/204012807-OpenDNS-Knowledge-Base",
                "https://support.opendns.com/hc/en-us/categories/204012907-OpenDNS-Device-Configuration"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://www.opendns.com/",
            'logo': "https://d15ni2z53ptwz9.cloudfront.net/opendns-www/img/logo-opendns.png",
            'description': "Cisco Umbrella provides protection against threats on the internet such as "
            "malware, phishing, and ransomware.\n"
            "OpenDNS is a suite of consumer products aimed at making your internet faster, safer, and more reliable. "
            "FamilyShield is the single easiest way to protect your kids online, block adult websites, "
            "and protect your family from phishing and malware.",
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None

    checks = {
        "146.112.61.105": "OpenDNS - Botnet",
        "146.112.61.106": "OpenDNS - Adult",
        "146.112.61.107": "OpenDNS - Malware",
        "146.112.61.108": "OpenDNS - Phishing",
        "146.112.61.109": "OpenDNS - Blocked",
        "146.112.61.110": "OpenDNS - Malware",
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

    def queryAddr(self, qaddr):
        if not qaddr:
            return None

        res = dns.resolver.Resolver()
        res.nameservers = ["208.67.222.123", "208.67.220.123"]

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

        self.debug(f"{eventData} found in OpenDNS Blocklist: {res}")

        for result in res:
            k = str(result)
            if k not in self.checks:
                continue

            evt = SpiderFootEvent(blacklist_type, f"{self.checks[k]} [{eventData}]", self.__name__, event)
            self.notifyListeners(evt)

            if k in ['146.112.61.105', '146.112.61.107', '146.112.61.108', '146.112.61.110']:
                evt = SpiderFootEvent(malicious_type, f"{self.checks[k]} [{eventData}]", self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_opendns class
