# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_intfiles
# Purpose:      From Spidering and from searching search engines, identifies
#               files of potential interest.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import urllib
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_intfiles(SpiderFootPlugin):
    """Interesting Files:Footprint:Crawling and Scanning::Identifies potential files of interest, e.g. office documents, zip files."""


    # Default options
    opts = {
        'pages': 20,  # Number of search results pages to iterate
        'fileexts': ["doc", "docx", "ppt", "pptx", "pdf", 'xls', 'xlsx', 'zip'],
        'usesearch': True,
        'searchengine': "yahoo"
    }

    # Option descriptions
    optdescs = {
        'pages': "Number of search engine results pages to iterate through if using one.",
        'fileexts': "File extensions of files you consider interesting.",
        'usesearch': "Use search engines to quickly find files. If false, only spidering will be used.",
        'searchengine': "If using a search engine, which one? google, yahoo or bing."
    }

    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME", "LINKED_URL_INTERNAL"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SEARCH_ENGINE_WEB_CONTENT", "INTERESTING_FILE"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventName == "INTERNET_NAME" and not self.opts['usesearch']:
            self.sf.debug("Not using a search engine to find interesting files.")
            return None

        if eventData in self.results:
            return None

        if eventName == "LINKED_URL_INTERNAL":
            for fileExt in self.opts['fileexts']:
                if "." + fileExt.lower() in eventData.lower():
                    if eventData in self.results:
                        continue
                    else:
                        self.results.append(eventData)

                    evt = SpiderFootEvent("INTERESTING_FILE", eventData,
                                          self.__name__, event)
                    self.notifyListeners(evt)
            return None

        if eventData not in self.results:
            self.results.append(eventData)

        # Handling INTERNET_NAME event..
        for fileExt in self.opts['fileexts']:
            # Sites hosted on the domain
            if self.opts['searchengine'].lower() == "google":
                pages = self.sf.googleIterate("site:" + eventData + "+" +
                                              "%2Bext:" + fileExt, dict(limit=self.opts['pages'],
                                                                        useragent=self.opts['_useragent'],
                                                                        timeout=self.opts['_fetchtimeout']))
                self.__dataSource__ = "Google"

            if self.opts['searchengine'].lower() == "bing":
                pages = self.sf.bingIterate("site:" + eventData + "+" +
                                            "%2Bfiletype:" + fileExt, dict(limit=self.opts['pages'],
                                                                      useragent=self.opts['_useragent'],
                                                                      timeout=self.opts['_fetchtimeout']))
                self.__dataSource__ = "Bing"

            if self.opts['searchengine'].lower() == "yahoo":
                pages = self.sf.yahooIterate("site:" + eventData + "+" +
                                             "%2Bfiletype:" + fileExt, dict(limit=self.opts['pages'],
                                                                       useragent=self.opts['_useragent'],
                                                                       timeout=self.opts['_fetchtimeout']))
                self.__dataSource__ = "Yahoo"

            if pages is None:
                self.sf.info("No results returned from " + self.opts['searchengine'] +
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
                evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", pages[page],
                                      self.__name__, event)
                self.notifyListeners(evt)

                links = self.sf.parseLinks(page, pages[page], eventData)
                if len(links) == 0:
                    continue

                for link in links.keys():
                    if link in self.results:
                        continue

                    if self.opts['searchengine'] == "yahoo":
                        link = re.sub(r'.*RU=(.*?)/RK=.*', r'\1', link)

                    if self.sf.urlFQDN(link).endswith(eventData):
                        # This for loop might seem redundant but sometimes search engines return results
                        # for other file extensions.
                        for fe in self.opts['fileexts']:
                            if "." + fe.lower() in link.lower():
                                self.sf.info("Found an interesting file: " + link)
                                evt = SpiderFootEvent("INTERESTING_FILE", link,
                                                      self.__name__, event)
                                self.notifyListeners(evt)
                                self.results.append(link)

# End of sfp_intfiles class
