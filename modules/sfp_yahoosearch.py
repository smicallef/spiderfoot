#-------------------------------------------------------------------------------
# Name:         sfp_yahoosearch
# Purpose:      Searches Yahoo for content related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/04/2014
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

class sfp_yahoosearch(SpiderFootPlugin):
    """Yahoo:Some light Yahoo scraping to identify sub-domains and links."""

    # Default options
    opts = {
        'fetchlinks':   True,   # Should we fetch links on the base domain?
        'pages':        20      # Number of yahoo results pages to iterate
    }

    # Option descriptions
    optdescs = {
        'fetchlinks': "Fetch links found on the target domain-name?",
        'pages':    "Number of Yahoo results pages to iterate through."
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
        return [ "LINKED_URL_INTERNAL", "SEARCH_ENGINE_WEB_CONTENT", 
            "CO_HOSTED_SITE" ]

    def yahooCleaner(self, string):
        return " url=\"" + urllib.unquote(string.group(1)) + "\" "

    def start(self):
        # Sites hosted on the domain
        pages = sf.yahooIterate("site:" + self.baseDomain, dict(limit=self.opts['pages'],
            useragent=self.opts['_useragent'], timeout=self.opts['_fetchtimeout']))
        if pages == None:
            sf.info("No results returned from Yahoo.")
            return None

        for page in pages.keys():
            if page in self.results:
                continue
            else:
                self.results.append(page)

            # Check if we've been asked to stop
            if self.checkForStop():
                return None

            content = re.sub("RU=(.[^\/]+)\/RK=", self.yahooCleaner, pages[page])

            # Submit the yahoo results for analysis
            evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", content, self.__name__)
            self.notifyListeners(evt)

            # We can optionally fetch links to our domain found in the search
            # results. These may not have been identified through spidering.
            if self.opts['fetchlinks']:
                links = sf.parseLinks(page, content, self.baseDomain)
                if len(links) == 0:
                    continue

                for link in links:
                    if link in self.results:
                        continue
                    else:
                        self.results.append(link)
                    if sf.urlBaseUrl(link).endswith(self.baseDomain):
                        sf.debug("Found a link: " + link)
                        if self.checkForStop():
                            return None

                        evt = SpiderFootEvent("LINKED_URL_INTERNAL", link, self.__name__)
                        self.notifyListeners(evt)

# End of sfp_yahoosearch class
