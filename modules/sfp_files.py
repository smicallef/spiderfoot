#-------------------------------------------------------------------------------
# Name:         sfp_files
# Purpose:      Searches Google for files of potential interest.
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

class sfp_files(SpiderFootPlugin):
    """Files:Identifies potential files of interest, e.g. office documents."""

    # Default options
    opts = {
        'pages':        20,      # Number of google results pages to iterate
        'fileexts':     [ "doc", "docx", "ppt", "pptx", "pdf", "zip", "txt", 
                        "rtf", "old", "tmp" ]
    }

    # Option descriptions
    optdescs = {
        'pages':    "Number of search results pages to iterate through.",
        'fileexts': "File extensions of files you consider interesting."
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
        return [ "SEARCH_ENGINE_WEB_CONTENT", "INTERESTING_FILE" ]

    def start(self):
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

                # Fetch the PasteBin page
                links = sf.parseLinks(page, pages[page], self.baseDomain)
                if len(links) == 0:
                    continue

                for link in links:
                    if link in self.results:
                        continue
                    else:
                        self.results.append(link)

                    sf.debug("Found a link: " + link)
                    if sf.urlBaseUrl(link).endswith(self.baseDomain) and \
                        "." + fileExt in link:
                        if self.checkForStop():
                            return None

                        evt = SpiderFootEvent("INTERESTING_FILE", link, self.__name__)
                        self.notifyListeners(evt)

# End of sfp_files class
