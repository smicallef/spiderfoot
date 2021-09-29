# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_onioncity
# Purpose:      Searches the Tor search engine 'Onion City' using Google Custom
#               Search for content related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     15/07/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_onioncity(SpiderFootPlugin):

    meta = {
        'name': "Onion.link",
        'summary': "Search Tor 'Onion City' search engine for mentions of the target domain using Google Custom Search.",
        'flags': ["apikey", "tor"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://onion.link/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://developers.google.com/custom-search/v1",
                "https://developers.google.com/custom-search/docs/overview",
                "https://cse.google.com/cse"
            ],
            'apiKeyInstructions': [
                "Visit https://developers.google.com/custom-search/v1/introduction",
                "Register a free Google account",
                "Click on 'Get A Key'",
                "Connect a Project",
                "The API Key will be listed under 'YOUR API KEY'"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://onion.link",
            'logo': "https://onion.link/images/OC.png",
            'description': "Enabling search and global access to Tor's onionsites.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "cse_id": "013611106330597893267:tfgl3wxdtbp",
        'fetchlinks': True,
        'fullnames': True
    }

    # Option descriptions
    optdescs = {
        "api_key": "Google API Key for Onion.link search.",
        "cse_id": "Google Custom Search Engine ID.",
        'fetchlinks': "Fetch the darknet pages (via TOR, if enabled) to verify they mention your target.",
        'fullnames': "Search for human names?"
    }

    # Target
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
            return

        if not self.opts['fullnames'] and eventName == 'HUMAN_NAME':
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_onioncity but did not set a Google API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Already did a search for {eventData}, skipping.")
            return

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
            return

        urls = res["urls"]
        new_links = list(set(urls) - set(self.results.keys()))

        # Add new links to results
        for link in new_links:
            self.results[link] = True

        # Submit the Google results for analysis
        googlesearch_url = res["webSearchUrl"]
        response = self.sf.fetchUrl(
            googlesearch_url,
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts["_useragent"],
        )
        if response['code'] in ["200", "201", "202"]:
            evt = SpiderFootEvent(
                "RAW_RIR_DATA", response["content"], self.__name__, event
            )
            self.notifyListeners(evt)
        else:
            self.error("Failed to fetch Google web search URL")

        # Check if we've been asked to stop
        if self.checkForStop():
            return

        darknet_links = [
            link for link in new_links if self.sf.urlFQDN(link).endswith(".onion.link")
        ]

        for link in darknet_links:
            self.debug("Found a darknet mention: " + link)
            torlink = link.replace(".onion.link", ".onion")
            if self.opts['fetchlinks']:
                res = self.sf.fetchUrl(torlink, timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'],
                                       verify=False)

                if res['content'] is None:
                    self.debug("Ignoring " + link + " as no data returned")
                    continue

                # Sometimes onion city search results false positives
                if re.search(r"[^a-zA-Z\-\_0-9]" + re.escape(eventData)
                             + r"[^a-zA-Z\-\_0-9]", res['content'], re.IGNORECASE) is None:
                    self.debug("Ignoring " + link + " as no mention of " + eventData)
                    continue

                evt = SpiderFootEvent("DARKNET_MENTION_URL", torlink, self.__name__, event)
                self.notifyListeners(evt)

                try:
                    startIndex = res['content'].index(eventData) - 120
                    endIndex = startIndex + len(eventData) + 240
                except Exception:
                    self.debug("String not found in content.")
                    continue

                data = res['content'][startIndex:endIndex]
                evt = SpiderFootEvent("DARKNET_MENTION_CONTENT", "..." + data + "...",
                                      self.__name__, evt)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("DARKNET_MENTION_URL", torlink, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_onioncity class
