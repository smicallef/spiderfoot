# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_googlesearchdomain
# Purpose:      Searches Google for content related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_googlesearchdomain(SpiderFootPlugin):
    """Google Search, by domain:Footprint,Investigate,Passive:Search Engines:apikey:Some light Google scraping to identify sub-domains and links within site:domain contexts you specify."""


    # Default options
    opts = {
        "api_key": "", "cse_id": "", 'sites': ""
    }

    # Option descriptions
    optdescs = {
        "api_key": "Google API Key.",
        "cse_id": "Google Custom Search Engine ID.",
        'sites': "Comma-separated list of site: entries to search for your target. For example, specifying youtube.com,facebook.com will use Google to search within youtube.com and facebook.com for mentions of your target. This should NOT be set to the domain name of your target, because that is what the sfp_googlesearch module will cover."
    }

    # Target
    results = list()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()
        self.__dataSource__ = "Google"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["LINKED_URL_EXTERNAL", "SEARCH_ENGINE_WEB_CONTENT"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if eventData in self.results:
            self.sf.debug("Already did a search for " + eventData + ", skipping.")
            return None
        else:
            self.results.append(eventData)

        if len(self.opts['sites']) == 0:
            self.sf.error("You enabled sfp_googlesearchdomain but did not specify any sites!", False)
            self.errorState = True
            return None

        for dom in self.opts['sites'].split(","):
            if self.checkForStop():
                return None

            # Sites hosted on the domain
            results = self.sf.googleIterate(
                searchString=eventData + "+site:" + dom,
                opts={
                    "timeout": self.opts["_fetchtimeout"],
                    "useragent": self.opts["_useragent"],
                    "api_key": self.opts["api_key"],
                    "cse_id": self.opts["cse_id"],
                },
            )
            if results is None:
                # Failed to talk to the Google API or no results returned
                return None

            urls = results["urls"]
            new_links = list(set(urls) - set(self.results))

            # Add new links to results
            self.results.extend(new_links)

            relevant_links = [
                link for link in new_links if self.sf.urlFQDN(link).endswith(dom)
            ]
            for link in relevant_links:
                self.sf.debug("Found a link: " + link)

                evt = SpiderFootEvent("LINKED_URL_INTERNAL", link, self.__name__, event)
                self.notifyListeners(evt)

            if relevant_links:
                # Submit the Google results for analysis
                googlesearch_url = results["webSearchUrl"]
                response = self.sf.fetchUrl(
                    googlesearch_url,
                    timeout=self.opts["_fetchtimeout"],
                    useragent=self.opts["_useragent"],
                )
                if response['status'] == 'OK':
                    evt = SpiderFootEvent(
                        "SEARCH_ENGINE_WEB_CONTENT", response["content"], self.__name__, event
                    )
                    self.notifyListeners(evt)
                else:
                    self.sf.error("Failed to fetch Google web search URL", exception=False)

# End of sfp_googlesearchdomain class
