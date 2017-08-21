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
    """Google Search, by domain:Footprint,Investigate,Passive:Search Engines:errorprone:Some light Google scraping to identify sub-domains and links within site:domain contexts you specify."""


    # Default options
    opts = {
        'pages': 20,  # Number of google results pages to iterate
        'sites': ""
    }

    # Option descriptions
    optdescs = {
        'pages': "Number of Google results pages to iterate through.",
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
            pages = self.sf.googleIterate(eventData + "%20site:" + dom,
                                          dict(limit=self.opts['pages'], useragent=self.opts['_useragent'],
                                          timeout=self.opts['_fetchtimeout']))
            if pages is None:
                self.sf.info("No results returned from Google for " + dom + ".")
                return None

            for page in pages.keys():
                found = False
                if page in self.results:
                    continue
                else:
                    self.results.append(page)

                links = self.sf.parseLinks(page, pages[page], dom)
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
                    if self.sf.urlFQDN(link).endswith(dom):
                        found = True
                        evt = SpiderFootEvent("LINKED_URL_EXTERNAL", link,
                                              self.__name__, event)
                        self.notifyListeners(evt)

                if found:
                    # Submit the google results for analysis
                    evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", pages[page],
                                          self.__name__, event)
                    self.notifyListeners(evt)


# End of sfp_googlesearchdomain class
