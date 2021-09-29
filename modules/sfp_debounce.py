# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_debounce
# Purpose:      Spiderfoot plugin to check if an email is
#               disposable using Debounce API.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     2020-10-01
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_debounce(SpiderFootPlugin):

    meta = {
        'name': "Debounce",
        'summary': "Check whether an email is disposable",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://debounce.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://debounce.io/free-disposable-check-api/"
            ],
            'favIcon': "https://debounce.io/wp-content/uploads/2018/01/favicon-2.png",
            'logo': "https://debounce.io/wp-content/uploads/2018/01/debounce-logo-2.png",
            'description': "DeBounce provides a free & powerful API endpoint for checking "
            "a domain or email address against a realtime up-to-date list of disposable domains."
            "CORS is enabled for all originating domains, "
            "so you can call the API directly from your client-side code.",
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "EMAILADDR"
        ]

    def producedEvents(self):
        return [
            "EMAILADDR_DISPOSABLE",
            "RAW_RIR_DATA"
        ]

    def queryEmailAddr(self, qry):
        res = self.sf.fetchUrl(
            f"https://disposable.debounce.io?email={qry}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )

        if res['content'] is None:
            self.info(f"No Debounce info found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from Debounce: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        self.results[eventData] = True

        data = self.queryEmailAddr(eventData)

        if data is None:
            return

        isDisposable = data.get('disposable')

        if isDisposable == "true":
            evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
            self.notifyListeners(evt)

            evt = SpiderFootEvent("EMAILADDR_DISPOSABLE", eventData, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_debounce class
