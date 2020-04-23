# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_creditcard
# Purpose:      Example module to use for new modules.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     21/04/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_creditcard(SpiderFootPlugin):

    """Credit Card Extractor:Footprint,Investigate,Passive:Content Analysis::Identify Credit Card Numbers in any data"""

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
        # Krishnasis - Note : What does self.tempStorage() return ?
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT"]

    # What events this module produces
    def producedEvents(self):
        return ["CREDIT_CARD_NUMBER"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        event.moduleDataSource="Target Website"

        # Once we are in this state, return immediately.
        if self.errorState:
            return None

        # event was received.
        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Extract Credit Card numbers
        creditCards=self.sf.parseCreditCards(eventData)

        myres=list()
        for creditCard in creditCards:
            evttype="CREDIT_CARD_NUMBER"
            
            self.sf.info("Found credit card number : "+creditCard)

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
