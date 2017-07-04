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
    """PasteBin:Footprint,Investigate,Passive:Leaks, Dumps and Breaches:errorprone:PasteBin scraping (via Google) to identify related content."""


    # Default options
    opts = {
        'searchpages': 20  # Number of google results pages to iterate
    }

    # Option descriptions
    optdescs = {
        'searchpages': "Number of search results pages to iterate through."
    }

    domains = {
        'pastebin': "pastebin.com"
    }

    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

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

        if eventData in self.results:
            return None
        else:
            self.results.append(eventData)

        for dom in self.domains.keys():
            links = list()
            target = self.domains[dom]
            pages = self.sf.googleIterate("site:" + target + "%20+\"" + eventData + "\"",
                                          dict(limit=self.opts['searchpages'],
                                          useragent=self.opts['_useragent'], 
                                          timeout=self.opts['_fetchtimeout']))

            if pages is None:
                self.sf.info("No results returned from Google search of " + target + ".")
                return None

            for page in pages.keys():
                if page in self.results:
                    continue
                else:
                    self.results.append(page)

                # Check if we've been asked to stop
                if self.checkForStop():
                    return None

                # Fetch the paste site content
                links += self.sf.parseLinks(page, pages[page], target)

            for link in links:
                if link in self.results:
                    continue
                else:
                    self.results.append(link)

                self.sf.debug("Found a link: " + link)
                if self.sf.urlBaseUrl(link).endswith(target):
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
