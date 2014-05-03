#-------------------------------------------------------------------------------
# Name:         sfp_intfiles
# Purpose:      From Spidering and from searching search engines, identifies
#               files of potential interest.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import random
import re
import time
import urllib
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_intfiles(SpiderFootPlugin):
    """Interesting Files:Identifies potential files of interest, e.g. office documents."""

    # Default options
    opts = {
        'pages':        20,      # Number of search results pages to iterate
        'fileexts':     [ "doc", "docx", "ppt", "pptx", "pdf", 'xls', 'xlsx' ],
        'usesearch':    True,
        'searchengine': "yahoo"
    }

    # Option descriptions
    optdescs = {
        'pages':    "Number of search engine results pages to iterate through if using one.",
        'fileexts': "File extensions of files you consider interesting.",
        'usesearch': "Use search engines to quickly find files. If false, only spidering will be used.",
        'searchengine': "If using a search engine, which one? google, yahoo or bing."
    }

    results = list()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ "DOMAIN_NAME", "LINKED_URL_INTERNAL" ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "SEARCH_ENGINE_WEB_CONTENT", "INTERESTING_FILE" ]

    def yahooCleaner(self, string):
        return " url=\"" + urllib.unquote(string.group(1)) + "\" "

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventName == "DOMAIN_NAME" and not self.opts['usesearch']:
            sf.debug("Not using a search engine to find interesting files.")
            return None

        if eventData in self.results:
            return None
        else:
            self.results.append(eventData)

        if eventName == "LINKED_URL_INTERNAL":
            for fileExt in self.opts['fileexts']:
                if "." + fileExt.lower() in eventData.lower():
                    if eventData in self.results:
                        continue
                    else:
                        self.results.append(eventData)
                    evt = SpiderFootEvent("INTERESTING_FILE", eventData, self.__name__)
                    self.notifyListeners(evt)
            return None

        # Handling DOMAIN_NAME event..
        for fileExt in self.opts['fileexts']:
            # Sites hosted on the domain
            if self.opts['searchengine'].lower() == "google":
                pages = sf.googleIterate("site:" + eventData + "+" + \
                    "%2Bext:" + fileExt, dict(limit=self.opts['pages'],
                    useragent=self.opts['_useragent'], 
                    timeout=self.opts['_fetchtimeout']))

            if self.opts['searchengine'].lower() == "bing":
                pages = sf.bingIterate("site:" + eventData + "+" + \
                    "%2Bext:" + fileExt, dict(limit=self.opts['pages'],
                    useragent=self.opts['_useragent'], 
                    timeout=self.opts['_fetchtimeout']))

            if self.opts['searchengine'].lower() == "yahoo":
                pages = sf.yahooIterate("site:" + eventData + "+" + \
                    "%2Bext:" + fileExt, dict(limit=self.opts['pages'],
                    useragent=self.opts['_useragent'], 
                    timeout=self.opts['_fetchtimeout']))

            if pages == None:
                sf.info("No results returned from " + self.opts['searchengine'] + \
                    " for " + fileExt + " files.")
                continue

            for page in pages.keys():
                if page in self.results:
                    continue
                else:
                    self.results.append(page)

                # Check if we've been asked to stop
                if self.checkForStop():
                    return None

                # Submit the gresults for analysis
                evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", pages[page], self.__name__)
                self.notifyListeners(evt)

                if self.opts['searchengine'].lower() == "yahoo":
                    res = re.sub("RU=(.[^\/]+)\/RK=", self.yahooCleaner,
                        pages[page], 0)
                else:
                    res = pages[page]

                links = sf.parseLinks(page, res, eventData)
                if len(links) == 0:
                    continue

                for link in links:
                    if link in self.results:
                        continue
                    else:
                        self.results.append(link)

                    if sf.urlBaseUrl(link).endswith(eventData) and \
                        "." + fileExt.lower() in link.lower():
                        sf.info("Found an interesting file: " + link)
                        evt = SpiderFootEvent("INTERESTING_FILE", link, self.__name__)
                        self.notifyListeners(evt)

# End of sfp_intfiles class
