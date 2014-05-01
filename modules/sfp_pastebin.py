#-------------------------------------------------------------------------------
# Name:         sfp_pastebin
# Purpose:      Searches Google for PasteBin content related to the domain in 
#               question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/03/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import random
import re
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_pastebin(SpiderFootPlugin):
    """PasteBin:PasteBin scraping (via Google) to identify related content."""

    # Default options
    opts = {
        'pages':        20      # Number of google results pages to iterate
    }

    # Option descriptions
    optdescs = {
        'pages':    "Number of search results pages to iterate through."
    }

    # Target
    baseDomain = None
    results = list()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return None

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "SEARCH_ENGINE_WEB_CONTENT", "PASTEBIN_CONTENT" ]

    def start(self):
        # Sites hosted on the domain
        pages = sf.googleIterate("site:pastebin.com+\"" + \
            self.baseDomain + "\"", dict(limit=self.opts['pages'],
            useragent=self.opts['_useragent'], timeout=self.opts['_fetchtimeout']))

        if pages == None:
            sf.info("No results returned from Google PasteBin search.")
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
            evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", pages[page], self.__name__)
            self.notifyListeners(evt)

            # Fetch the PasteBin page
            links = sf.parseLinks(page, pages[page], "pastebin.com")
            if len(links) == 0:
                continue

            for link in links:
                if link in self.results:
                    continue
                else:
                    self.results.append(link)

                sf.debug("Found a link: " + link)
                if sf.urlBaseUrl(link).endswith("pastebin.com"):
                    if self.checkForStop():
                        return None

                    res = sf.fetchUrl(link, timeout=self.opts['_fetchtimeout'],
                        useragent=self.opts['_useragent'])

                    if res['content'] == None:
                        sf.debug("Ignoring " + link + " as no data returned")
                        continue

                    evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT",
                        res['content'], self.__name__)
                    self.notifyListeners(evt)

                    # Sometimes pastebin search results false positives
                    if re.search("[^a-zA-Z\-\_]" + re.escape(self.baseDomain) + \
                        "[^a-zA-Z\-\_]", res['content'], re.IGNORECASE) == None:
                        continue

                    startIndex = res['content'].index(self.baseDomain)-120
                    endIndex = startIndex+len(self.baseDomain)+240
                    data = res['content'][startIndex:endIndex]

                    evt = SpiderFootEvent("PASTEBIN_CONTENT",
                        "<SFURL>" + link + "</SFURL>\n" + "\"... " + data + " ...\"", 
                        self.__name__)
                    self.notifyListeners(evt)


# End of sfp_pastebin class
