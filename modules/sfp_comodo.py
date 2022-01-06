# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_comodo
# Purpose:     SpiderFoot plug-in for looking up whether hosts are blocked by
#              Comodo Secure DNS.
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
        'name': "Comodo Secure DNS",
        'summary': "Check if a host would be blocked by Comodo Secure DNS.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.comodo.com/secure-dns/",
            'model': "FREE_NOAUTH_LIMITED",
            'references': [
                "https://cdome.comodo.com/pdf/Datasheet-Dome-Shield.pdf",
                "http://securedns.dnsbycomodo.com/",
                "https://www.comodo.com/secure-dns/secure-dns-assets/dowloads/ccs-dome-shield-whitepaper-threat-intelligence.pdf",
                "https://www.comodo.com/secure-dns/secure-dns-assets/dowloads/domeshield-all-use-cases.pdf",
            ],
            'favIcon': "https://www.comodo.com/favicon.ico",
            'logo': "https://www.comodo.com/new-assets/images/logo.png",
            'description': "Comodo Secure DNS is a domain name resolution service "
            "that resolves your DNS requests through our worldwide network of redundant DNS servers, "
            "bringing you the most reliable fully redundant DNS service anywhere, for a safer, "
            "smarter and faster Internet experience."
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
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_COHOST",
        ]

    def query(self, qaddr):
        res = dns.resolver.Resolver()
        res.nameservers = ["8.26.56.26", "8.20.247.20"]

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

        # Check that it resolves first, as it becomes a valid
        # malicious host only if NOT resolved by Comodo Secure DNS.
        if not self.sf.resolveHost(eventData) and not self.sf.resolveHost6(eventData):
            return

        found = self.query(eventData)

        # Host was found, not blocked
        if found:
            return

        evt = SpiderFootEvent(blacklist_type, f"Comodo Secure DNS [{eventData}]", self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent(malicious_type, f"Comodo Secure DNS [{eventData}]", self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_comodo class
