# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_fortinet
# Purpose:      Check if an IP address is malicious according to FortiGuard Antispam.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_fortinet(SpiderFootPlugin):

    meta = {
        'name': "FortiGuard Antispam",
        'summary': "Check if an IP address is malicious according to FortiGuard Antispam.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.fortiguard.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.fortiguard.com/learnmore#as",
            ],
            'favIcon': "https://www.fortiguard.com/static/images/favicon.ico",
            'logo': "https://www.fortiguard.com/static/images/Fortinet-logo%20white.png?v=880",
            'description': "FortiGuard Antispam provides a comprehensive and multi-layered approach to detect and filter spam processed by organizations."
        }
    }

    # Default options
    opts = {
        'checkaffiliates': True
    }

    # Option descriptions
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

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "IPV6_ADDRESS", "AFFILIATE_IPADDR", "AFFILIATE_IPV6_ADDRESS"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_AFFILIATE_IPADDR"]

    def query(self, ip):
        if not ip:
            return None

        res = self.sf.fetchUrl(
            f"https://www.fortiguard.com/search?q={ip}&engine=8",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from FortiGuard Antispam.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from FortiGuard Antispam")
            self.errorState = True
            return None

        return res['content']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            evtType = 'MALICIOUS_IPADDR'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            if not self.opts.get('checkaffiliates', False):
                return
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
        else:
            return

        data = self.query(eventData)

        if not data:
            return

        if "Your signature is on the blocklist" in data:
            url = f"https://www.fortiguard.com/search?q={eventData}&engine=8"
            text = f"FortiGuard Antispam [{eventData}]\n<SFURL>{url}</SFURL>"
            evt = SpiderFootEvent(evtType, text, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_fortinet class
