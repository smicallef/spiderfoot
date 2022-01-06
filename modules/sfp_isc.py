# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_isc
# Purpose:      Check if an IP address is malicious according to SANS ISC.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_isc(SpiderFootPlugin):

    meta = {
        'name': "Internet Storm Center",
        'summary': "Check if an IP address is malicious according to SANS ISC.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://isc.sans.edu",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://isc.sans.edu/api/",
                "https://isc.sans.edu/howto.html",
                "https://isc.sans.edu/honeypot.html",
                "https://isc.sans.edu/glossary.html",
                "https://isc.sans.edu/fightback.html"
            ],
            'favIcon': "https://isc.sans.edu/iscfavicon.ico",
            'logo': "https://isc.sans.edu/images/logos/isc/large.png",
            'description': "The ISC provides a free analysis and warning service to thousands of Internet users "
            "and organizations, and is actively working with Internet Service Providers to "
            "fight back against the most malicious attackers.\n"
            "Thousands of sensors that work with most firewalls, intrusion detection systems, "
            "home broadband devices, and nearly all operating systems are constantly collecting information about "
            "unwanted traffic arriving from the Internet. "
            "These devices feed the DShield database where human volunteers as well as machines pour through "
            "the data looking for abnormal trends and behavior. "
            "The resulting analysis is posted to the ISC's main web page where it can be automatically retrieved "
            "by simple scripts or can be viewed in near real time by any Internet user.",
        }
    }

    opts = {
        'checkaffiliates': True
    }

    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
        ]

    def query(self, ip):
        if not ip:
            return None

        res = self.sf.fetchUrl(
            f"https://isc.sans.edu/api/ip/{ip}",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from ISC.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from ISC")
            self.errorState = True
            return None

        return res['content']

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            malicious_type = 'MALICIOUS_IPADDR'
            blacklist_type = 'BLACKLISTED_IPADDR'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = 'MALICIOUS_AFFILIATE_IPADDR'
            blacklist_type = 'BLACKLISTED_AFFILIATE_IPADDR'
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        data = self.query(eventData)

        if not data:
            return

        attacks = re.findall(r"<attacks>([0-9]+)</attacks>", data)

        if not attacks:
            return

        url = f"https://isc.sans.edu/api/ip/{eventData}"
        text = f"Internet Storm Center [{eventData}]\n<SFURL>{url}</SFURL>"

        evt = SpiderFootEvent(malicious_type, text, self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent(blacklist_type, text, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_isc class
