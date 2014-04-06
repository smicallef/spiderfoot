#-------------------------------------------------------------------------------
# Name:         sfp_intfiles
# Purpose:      From Spidering and from searching Google, identifies files of 
#               potential interest.
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
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_intfiles(SpiderFootPlugin):
    """Interesting Files:Identifies potential files of interest, e.g. office documents."""

    # Default options
    opts = {
        'pages':        20,      # Number of google results pages to iterate
        'fileexts':     [ "doc", "docx", "ppt", "pptx", "pdf", 'xls', 'xlsx' ],
        'usegoogle':    True
    }

    # Option descriptions
    optdescs = {
        'pages':    "Number of Google search results pages to iterate through if using Google.",
        'fileexts': "File extensions of files you consider interesting.",
        'usegoogle': "Use Google to quickly find files. If false, only spidering will be used."
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
        return [ "LINKED_URL_INTERNAL" ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "SEARCH_ENGINE_WEB_CONTENT", "INTERESTING_FILE" ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        for fileExt in self.opts['fileexts']:
            if "." + fileExt in eventData:
                evt = SpiderFootEvent("INTERESTING_FILE", eventData, self.__name__)
                self.notifyListeners(evt)


    def start(self):
        if not self.opts['usegoogle']:
            return None

        for fileExt in self.opts['fileexts']:
            # Sites hosted on the domain
            pages = sf.googleIterate("site:" + self.baseDomain + "+" + \
                "%2Bext:" + fileExt, dict(limit=self.opts['pages'],
                useragent=self.opts['_useragent'], timeout=self.opts['_fetchtimeout']))

            if pages == None:
                sf.info("No results returned from Google for " + fileExt + " files.")
                continue

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

                links = sf.parseLinks(page, pages[page], self.baseDomain)
                if len(links) == 0:
                    continue

                for link in links:
                    if link in self.results:
                        continue
                    else:
                        self.results.append(link)

                    sf.debug("Found an interesting file: " + link)
                    if sf.urlBaseUrl(link).endswith(self.baseDomain) and \
                        "." + fileExt in link:
                        evt = SpiderFootEvent("INTERESTING_FILE", link, self.__name__)
                        self.notifyListeners(evt)

# End of sfp_intfiles class
