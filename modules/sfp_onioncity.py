# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_onioncity
# Purpose:      Searches the Tor search engine 'Onion City' for content related 
#               to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     15/07/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
import re

class sfp_onioncity(SpiderFootPlugin):
    """Onion.link:Footprint,Investigate:Search Engines:apikey:Search Tor 'Onion City' search engine for mentions of the target domain."""


    # Default options
    opts = {
        "api_key": "", 
        "cse_id": "013611106330597893267:tfgl3wxdtbp", 
        'fetchlinks': True
    }

    # Option descriptions
    optdescs = {
        "api_key": "Google API Key for Onion.link search.",
        "cse_id": "Google Custom Search Engine ID.",
        'fetchlinks': "Fetch the darknet pages (via TOR, if enabled) to verify they mention your target."
    }

    # Target
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
        return ["INTERNET_NAME", "DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DARKNET_MENTION_URL", "DARKNET_MENTION_CONTENT", 
                "RAW_RIR_DATA"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_onioncity but did not set a Google API key!", False)
            self.errorState = True
            return None

        if eventData in self.results:
            self.sf.debug("Already did a search for " + eventData + ", skipping.")
            return None
        else:
            self.results[eventData] = True

        # Sites hosted on the domain
        res = self.sf.googleIterate(
            searchString="+site:onion.link " + eventData,
            opts={
                "timeout": self.opts["_fetchtimeout"],
                "useragent": self.opts["_useragent"],
                "api_key": self.opts["api_key"],
                "cse_id": self.opts["cse_id"],
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

        # Submit the Google results for analysis
        googlesearch_url = res["webSearchUrl"]
        response = self.sf.fetchUrl(
            googlesearch_url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts["_useragent"],
        )
        if response['code'].startswith('2'):
            evt = SpiderFootEvent(
                "RAW_RIR_DATA", response["content"], self.__name__, event
            )
            self.notifyListeners(evt)
        else:
            self.sf.error("Failed to fetch Google web search URL", exception=False)

        # Check if we've been asked to stop
        if self.checkForStop():
            return None

        darknet_links = [
            link for link in new_links if self.sf.urlFQDN(link).endswith(".onion.link")
        ]

        for link in darknet_links:
            self.sf.debug("Found a darknet mention: " + link)
            torlink = link.replace(".onion.link", ".onion")
            if self.opts['fetchlinks']:
                res = self.sf.fetchUrl(torlink, timeout=self.opts['_fetchtimeout'],
                                        useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.sf.debug("Ignoring " + link + " as no data returned")
                    continue

                # Sometimes onion city search results false positives
                if re.search("[^a-zA-Z\-\_0-9]" + re.escape(eventData) +
                                "[^a-zA-Z\-\_0-9]", res['content'], re.IGNORECASE) is None:
                    self.sf.debug("Ignoring " + link + " as no mention of " + eventData)
                    continue

                evt = SpiderFootEvent("DARKNET_MENTION_URL", torlink, self.__name__, event)
                self.notifyListeners(evt)

                try:
                    startIndex = res['content'].index(eventData) - 120
                    endIndex = startIndex + len(eventData) + 240
                except BaseException as e:
                    self.sf.debug("String not found in content.")
                    continue

                data = res['content'][startIndex:endIndex]
                evt = SpiderFootEvent("DARKNET_MENTION_CONTENT", "..." + data + "...", 
                                        self.__name__, evt)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("DARKNET_MENTION_URL", torlink, self.__name__, event)
                self.notifyListeners(evt)


# End of sfp_onioncity class
