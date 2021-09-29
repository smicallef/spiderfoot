# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_creditcard
# Purpose:      SpiderFoot plug-in for scanning retrieved content by other
#               modules (such as sfp_spider) and identifying credit card numbers.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     21/04/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_creditcard(SpiderFootPlugin):

    meta = {
        'name': "Credit Card Number Extractor",
        'summary': "Identify Credit Card Numbers in any data",
        'flags': ["errorprone"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    opts = {
    }

    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        # Override datasource for sfp_creditcard module
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DARKNET_MENTION_CONTENT", "LEAKSITE_CONTENT"]

    # What events this module produces
    def producedEvents(self):
        return ["CREDIT_CARD_NUMBER"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        creditCards = self.sf.parseCreditCards(eventData)

        for creditCard in set(creditCards):
            self.info(f"Found credit card number: {creditCard}")
            evt = SpiderFootEvent("CREDIT_CARD_NUMBER", creditCard, self.__name__, event)
            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"
            self.notifyListeners(evt)

# End of sfp_creditcard class
