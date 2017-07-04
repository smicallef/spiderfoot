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
    """Bing:Footprint,Investigate,Passive:Search Engines:errorprone:Some light Bing scraping to identify sub-domains and links."""


    # Default options
    opts = {
        'pages': 20  # Number of bing results pages to iterate
    }

    # Option descriptions
    optdescs = {
        'pages': "Number of Bing results pages to iterate through."
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
        pages = self.sf.bingIterate("site:" + eventData, dict(limit=self.opts['pages'],
                                                              useragent=self.opts['_useragent'],
                                                              timeout=self.opts['_fetchtimeout']))
        if pages is None:
            self.sf.info("No results returned from Bing.")
            return None

        for page in pages.keys():
            found = False
            if page in self.results:
                continue
            else:
                self.results.append(page)

            links = self.sf.parseLinks(page, pages[page], eventData)
            if len(links) == 0:
                continue

            for link in links:
                if self.checkForStop():
                    return None

                if link in self.results:
                    continue
                else:
                    self.results.append(link)
                if self.sf.urlFQDN(link).endswith(eventData):
                    found = True
                    self.sf.debug("Found a link: " + link)

                    evt = SpiderFootEvent("LINKED_URL_INTERNAL", link,
                                          self.__name__, event)
                    self.notifyListeners(evt)

            if found:
                # Submit the bing results for analysis
                evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", pages[page],
                                      self.__name__, event)
                self.notifyListeners(evt)


# End of sfp_bingsearch class
