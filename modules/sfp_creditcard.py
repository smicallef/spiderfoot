# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_creditcard
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) and identifying credit card numbers.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     21/04/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_creditcard(SpiderFootPlugin):
    """Credit Card Number Extractor:Footprint,Investigate,Passive:Content Analysis::Identify Credit Card Numbers in any data"""

    # Default options.
    opts = {
         # Options specific to this module
    }

    # Option descriptions.
    optdescs = {
    }

    # Tracking results can be helpful to avoid reporting/processing duplicates
    results = None

    # Tracking the error state of the module can be useful to detect when a third party
    # has failed and you don't wish to process any more events.
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        # Override datasource for sfp_creditcard module
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT", "DARKNET_MENTION_CONTENT",
                "LEAKSITE_CONTENT" ]

    # What events this module produces
    def producedEvents(self):
        return ["CREDIT_CARD_NUMBER"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # Once we are in this state, return immediately.
        if self.errorState:
            return None

        # event was received.
        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        # Extract Credit Card numbers
        creditCards = self.sf.parseCreditCards(eventData)

        myres = list()
        for creditCard in creditCards:
            evttype = "CREDIT_CARD_NUMBER"
            
            self.sf.info("Found credit card number : " + creditCard)

            if creditCard in myres:
                self.sf.debug("Already found from this source")
                continue
            myres.append(creditCard)
            
            evt = SpiderFootEvent(evttype, creditCard, self.__name__, event)
            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"
            self.notifyListeners(evt)

        return None
# End of sfp_creditcard class
