# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_googlesearch
# Purpose:      Searches Google for content related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_googlesearch(SpiderFootPlugin):
    """Google:Footprint,Investigate,Passive:Search Engines:errorprone:Some light Google scraping to identify sub-domains and links."""


    # Default options
    opts = {
        'pages': 20  # Number of google results pages to iterate
    }

    # Option descriptions
    optdescs = {
        'pages': "Number of Google results pages to iterate through."
    }

    # Target
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
        pages = self.sf.googleIterate("site:" + eventData,
                                      dict(limit=self.opts['pages'], useragent=self.opts['_useragent'],
                                           timeout=self.opts['_fetchtimeout']))
        if pages is None:
            self.sf.info("No results returned from Google.")
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
                self.sf.debug("Found a link: " + link)
                if self.sf.urlFQDN(link).endswith(eventData):
                    found = True
                    evt = SpiderFootEvent("LINKED_URL_INTERNAL", link,
                                          self.__name__, event)
                    self.notifyListeners(evt)

            if found:
                # Submit the google results for analysis
                evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", pages[page],
                                      self.__name__, event)
                self.notifyListeners(evt)


# End of sfp_googlesearch class
