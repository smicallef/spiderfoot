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
    """Bing:Footprint,Investigate,Passive:Search Engines::Obtain information from bing to identify sub-domains and links."""

    # Default options
    opts = {"pages": 20, "api_key": ""}

    # Option descriptions
    optdescs = {
        "pages": "Number of max bing results to request from api.",
        "api_key": "Bing API Key.",
    }

    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["LINKED_URL_INTERNAL", "SEARCH_ENGINE_WEB_CONTENT"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        if eventData in self.results:
            self.sf.debug("Already did a search for " + eventData + ", skipping.")
            return None
        else:
            self.results.append(eventData)

        # Sites hosted on the domain

        results = self.sf.bingIterate(
            searchString="site:" + eventData,
            opts={
                "timeout": self.opts["_fetchtimeout"],
                "useragent": self.opts["_useragent"],
                "count": self.opts["pages"],
                "api_key": self.opts["api_key"],
            },
        )
        if results is None:
            # Failed to talk to bing api or no results returned
            return None
        urls = results["urls"]
        new_links = list(set(urls) - set(self.results))

        # Add new links to results
        self.results.extend(new_links)

        internal_links = [
            link for link in new_links if self.sf.urlFQDN(link).endswith(eventData)
        ]
        for link in internal_links:
            self.sf.debug("Found a link: " + link)

            evt = SpiderFootEvent("LINKED_URL_INTERNAL", link, self.__name__, event)
            self.notifyListeners(evt)

        if internal_links:
            # Submit the bing results for analysis
            bingsearch_url = results["webSearchUrl"]
            response = self.sf.fetchUrl(
                bingsearch_url,
                timeout=self.opts["_fetchtimeout"],
                useragent=self.opts["_useragent"],
            )
            if response['status'] == 'OK':
                evt = SpiderFootEvent(
                    "SEARCH_ENGINE_WEB_CONTENT", response["content"], self.__name__, event
                )
                self.notifyListeners(evt)
            else:
                self.sf.error("Failed to fetch bing web search URL", exception=False)



# End of sfp_bingsearch class
