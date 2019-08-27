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
import requests
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_bingsearch(SpiderFootPlugin):
    """Bing:Footprint,Investigate,Passive:Search Engines::Some light Bing scraping to identify sub-domains and links."""

    # Default options
    opts = {"pages": 20}  # Number of max bing results to request from api

    # Option descriptions
    optdescs = {"pages": "Number of max bing results to request from api."}

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
        endpoint = "https://api.cognitive.microsoft.com/bing/v7.0/search"
        # ToDO: figure out how to add credentials in config:
        key = ""
        response = requests.get(
            endpoint,
            timeout=self.opts["_fetchtimeout"],
            headers={
                "Ocp-Apim-Subscription-Key": key,
                "User-Agent": self.opts["_useragent"],
            },
            params={
                "q": "site:" + eventData,
                "responseFilter": "Webpages",
                "count": self.opts["pages"],
            },
        )
        if response.status_code != 200:
            message = "Failed to talk to Bing API, status code: %s, response: %s".format(
                response.status_code, response.text
            )
            self.error(message)

        links_in_page = [
            result["url"] for result in response.json()["webPages"]["value"]
        ]
        new_links = list(set(links_in_page) - set(self.results))

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
            bingsearch_url = response.json()["webPages"]["webSearchUrl"]
            response = self.sf.fetchUrl(
                bingsearch_url,
                timeout=self.opts["_fetchtimeout"],
                useragent=self.opts["_useragent"],
            )
            evt = SpiderFootEvent(
                "SEARCH_ENGINE_WEB_CONTENT", response["content"], self.__name__, event
            )
            self.notifyListeners(evt)


# End of sfp_bingsearch class
