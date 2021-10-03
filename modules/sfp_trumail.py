# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_trumail
# Purpose:      Spiderfoot plugin to check if an email is
#               disposable using trumail.io API.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     2020-10-02
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_trumail(SpiderFootPlugin):

    meta = {
        'name': "Trumail",
        'summary': "Check whether an email is disposable",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://trumail.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://trumail.io/documentation"
            ],
            'favIcon': "https://trumail.io/assets/favicon-32x32.png",
            'logo': "https://trumail.io/assets/images/trumail100.png",
            'description': "Trumail is a product that was built with the intention of providing "
            "an easy to use API to software professionals who value a quality audience. "
            "Your apps registration workflow is one of the most important and complex parts of your software "
            "and it's very important that you filter user credentials in a way that allows for future use. "
            "Invalid user credentials, particularly email addresses, should be deemed valid "
            "and deliverable at the time of signup - That's where we come in.",
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
            f"https://api.trumail.io/v2/lookups/json?email={qry}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )

        if res['content'] is None:
            self.info(f"No Trumail info found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from Trumail: {e}")

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

        if isDisposable:
            evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
            self.notifyListeners(evt)

            evt = SpiderFootEvent("EMAILADDR_DISPOSABLE", eventData, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_trumail class
