# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_iban
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) and identifying IBAN numbers.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     26/04/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_iban(SpiderFootPlugin):

    meta = {
        'name': "IBAN Number Extractor",
        'summary': "Identify IBAN Numbers in any data",
        'flags': ["errorprone"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    # Default options.
    opts = {
    }

    # Option descriptions.
    optdescs = {
    }

    # Tracking results can be helpful to avoid reporting/processing duplicates
    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        # Override datasource for sfp_iban module
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT", "DARKNET_MENTION_CONTENT",
                "LEAKSITE_CONTENT"]

    # What events this module produces
    def producedEvents(self):
        return ["IBAN_NUMBER"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Extract IBAN Card numbers
        ibanNumbers = self.sf.parseIBANNumbers(eventData)

        myres = list()
        for ibanNumber in ibanNumbers:
            evttype = "IBAN_NUMBER"

            self.sf.info("Found IBAN number : " + ibanNumber)

            if ibanNumber in myres:
                self.sf.debug("Already found from this source")
                continue
            myres.append(ibanNumber)

            evt = SpiderFootEvent(evttype, ibanNumber, self.__name__, event)
            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"
            self.notifyListeners(evt)

# End of sfp_iban class
