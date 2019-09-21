# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_bingsearch
# Purpose:      Searches Bing for content related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/10/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
# -------------------------------------------------------------------------------
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_bingsearch(SpiderFootPlugin):
    """Bing:Footprint,Investigate,Passive:Search Engines:apikey:Obtain information from bing to identify sub-domains and links."""

    # Default options
    opts = {
        "pages": 20,
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "pages": "Number of max bing results to request from the API.",
        "api_key": "Bing API Key for Bing search."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["LINKED_URL_INTERNAL", "RAW_RIR_DATA"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_bingsearch but did not set a Bing API key!", False)
            self.errorState = True
            return None

        if eventData in self.results:
            self.sf.debug("Already did a search for " + eventData + ", skipping.")
            return None
        else:
            self.results[eventData] = True

        # Sites hosted on the domain

        res = self.sf.bingIterate(
            searchString="site:" + eventData,
            opts={
                "timeout": self.opts["_fetchtimeout"],
                "useragent": self.opts["_useragent"],
                "count": self.opts["pages"],
                "api_key": self.opts["api_key"],
            },
        )
        if res is None:
            # Failed to talk to the bing API or no results returned
            return None

        urls = res["urls"]
        new_links = list(set(urls) - set(self.results.keys()))

        # Add new links to results
        for l in new_links:
            self.results[l] = True

        internal_links = [
            link for link in new_links if self.sf.urlFQDN(link).endswith(eventData)
        ]
        for link in internal_links:
            self.sf.debug("Found a link: " + link)

            evt = SpiderFootEvent("LINKED_URL_INTERNAL", link, self.__name__, event)
            self.notifyListeners(evt)

        if internal_links:
            evt = SpiderFootEvent(
                "RAW_RIR_DATA", str(res), self.__name__, event
            )
            self.notifyListeners(evt)



# End of sfp_bingsearch class
