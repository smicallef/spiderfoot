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
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_bingsearch(SpiderFootPlugin):

    meta = {
        'name': "Bing",
        'summary': "Obtain information from bing to identify sub-domains and links.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.bing.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.microsoft.com/en-us/azure/cognitive-services/bing-web-search/"
            ],
            'apiKeyInstructions': [
                "Visit https://azure.microsoft.com/en-in/services/cognitive-services/bing-web-search-api/",
                "Register a free account",
                "Select on Bing Custom Search",
                "The API keys are listed under 'Key1' and 'Key2' (both should work)"
            ],
            'favIcon': "https://www.bing.com/sa/simg/bing_p_rr_teal_min.ico",
            'logo': "https://www.bing.com/sa/simg/bing_p_rr_teal_min.ico",
            'description': "The Bing Search APIs let you build web-connected apps and services that "
            "find webpages, images, news, locations, and more without advertisements.",
        }
    }

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

        for opt in list(userOpts.keys()):
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
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_bingsearch but did not set a Bing API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug("Already did a search for " + eventData + ", skipping.")
            return

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
            return

        urls = res["urls"]
        new_links = list(set(urls) - set(self.results.keys()))

        # Add new links to results
        for link in new_links:
            self.results[link] = True

        internal_links = [
            link for link in new_links if self.sf.urlFQDN(link).endswith(eventData)
        ]
        for link in internal_links:
            self.debug("Found a link: " + link)

            evt = SpiderFootEvent("LINKED_URL_INTERNAL", link, self.__name__, event)
            self.notifyListeners(evt)

        if internal_links:
            evt = SpiderFootEvent(
                "RAW_RIR_DATA", str(res), self.__name__, event
            )
            self.notifyListeners(evt)

# End of sfp_bingsearch class
