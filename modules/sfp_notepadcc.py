# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_pastebin
# Purpose:      Searches Google for PasteBin content related to the domain in 
#               question.
#
# Original Author:      Steve Micallef <steve@binarypool.com> modify by ShellCodeNoobx
#
# Created:     20/03/2014      Modified 22/09/2015
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_notepadcc(SpiderFootPlugin):
    """NotePadcc:NotePadcc scraping (via Google) to identify related content."""

    # Default options
    opts = {
        'pages': 20  # Number of google results pages to iterate
    }

    # Option descriptions
    optdescs = {
        'pages': "Number of search results pages to iterate through."
    }

    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS", "EMAILADDR"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SEARCH_ENGINE_WEB_CONTENT", "NOTEPADCC_CONTENT"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results.append(eventData)

        # Sites hosted on the domain
        pages = self.sf.googleIterate("site:notepad.cc +\"" + eventData + "\"",
                                      dict(limit=self.opts['pages'],
                                           useragent=self.opts['_useragent'], timeout=self.opts['_fetchtimeout']))

        if pages is None:
            self.sf.info("No results returned from Google NotePad.cc search.")
            return None

        for page in pages.keys():
            if page in self.results:
                continue
            else:
                self.results.append(page)

            # Check if we've been asked to stop
            if self.checkForStop():
                return None

            # Submit the google results for analysis
            evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", pages[page],
                                  self.__name__, event)
            self.notifyListeners(evt)

            # Fetch the NotePad.cc page
            links = self.sf.parseLinks(page, pages[page], "notepad.cc")
            if len(links) == 0:
                continue

            for link in links:
                if link in self.results:
                    continue
                else:
                    self.results.append(link)

                self.sf.debug("Found a link: " + link)
                if self.sf.urlBaseUrl(link).endswith("notepad.cc"):
                    if self.checkForStop():
                        return None

                    res = self.sf.fetchUrl(link, timeout=self.opts['_fetchtimeout'],
                                           useragent=self.opts['_useragent'])

                    if res['content'] is None:
                        self.sf.debug("Ignoring " + link + " as no data returned")
                        continue

                    evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT",
                                          res['content'], self.__name__, event)
                    self.notifyListeners(evt)

                    # Sometimes pastebin search results false positives
                    if re.search("[^a-zA-Z\-\_0-9]" + re.escape(eventData) +
                                         "[^a-zA-Z\-\_0-9]", res['content'], re.IGNORECASE) is None:
                        continue

                    try:
                        startIndex = res['content'].index(eventData) - 120
                        endIndex = startIndex + len(eventData) + 240
                    except BaseException as e:
                        self.sf.debug("String not found in NotePad.cc content.")
                        continue

                    data = res['content'][startIndex:endIndex]

                    evt = SpiderFootEvent("NOTEPADCC_CONTENT",
                                          "<SFURL>" + link + "</SFURL>\n" + "\"... " + data + " ...\"",
                                          self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_notepadcc class
