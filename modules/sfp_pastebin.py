# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_pastebin
# Purpose:      Searches Google for PasteBin content related to the domain in 
#               question.
#
# Author:      Steve Micallef <steve@binarypool.com> and ShellCodeNoobx
#
# Created:     20/03/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_pastebin(SpiderFootPlugin):
    """PasteBin:Footprint,Investigate,Passive:Leaks, Dumps and Breaches:apikey:PasteBin scraping (via Google) to identify related content."""


    # Default options
    opts = {
        "api_key": "", 
        "cse_id": "013611106330597893267:tfgl3wxdtbp"
    }

    # Option descriptions
    optdescs = {
        "api_key": "Google API Key for PasteBin search.",
        "cse_id": "Google Custom Search Engine ID.",
    }

    domains = {
        'pastebin': "pastebin.com"
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
        return ["DOMAIN_NAME", "INTERNET_NAME", "EMAILADDR"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["LEAKSITE_CONTENT", "LEAKSITE_URL"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_pastebin but did not set a Google API key!", False)
            self.errorState = True
            return None

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        for dom in self.domains.keys():
            links = list()
            target = self.domains[dom]
            res = self.sf.googleIterate(
                searchString="+site:{target_site} \"{search_keyword}\"".format(
                    target_site=target,
                    search_keyword=eventData,
                ),
                opts={
                    "timeout": self.opts["_fetchtimeout"],
                    "useragent": self.opts["_useragent"],
                    "api_key": self.opts["api_key"],
                    "cse_id": self.opts["cse_id"],
                },
            )

            if res is None:
                # Failed to talk to the Google API or no results returned
                return None

            urls = res["urls"]
            new_links = list(set(urls) - set(self.results.keys()))

            # Add new links to results
            for l in new_links:
                self.results[l] = True

            relevant_links = [
                link for link in new_links if self.sf.urlBaseUrl(link).endswith(target)
            ]
            
            for link in relevant_links:
                self.sf.debug("Found a link: " + link)

                if self.checkForStop():
                    return None

                res = self.sf.fetchUrl(link, timeout=self.opts['_fetchtimeout'],
                                        useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.sf.debug("Ignoring " + link + " as no data returned")
                    continue

                # Sometimes pastes search results false positives
                if re.search("[^a-zA-Z\-\_0-9]" + re.escape(eventData) +
                                "[^a-zA-Z\-\_0-9]", res['content'], re.IGNORECASE) is None:
                    continue

                try:
                    startIndex = res['content'].index(eventData)
                except BaseException as e:
                    self.sf.debug("String not found in pastes content.")
                    continue

                evt1 = SpiderFootEvent("LEAKSITE_URL", link, self.__name__, event)
                self.notifyListeners(evt1)

                evt2 = SpiderFootEvent("LEAKSITE_CONTENT", res['content'], self.__name__, evt1)
                self.notifyListeners(evt2)


# End of sfp_pastebin class
