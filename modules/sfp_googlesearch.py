#-------------------------------------------------------------------------------
# Name:         sfp_googlesearch
# Purpose:      Searches Google for content related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
from sflib import SpiderFoot, SpiderFootPlugin

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_googlesearch(SpiderFootPlugin):
    """Some light Google scraping to identify links for spidering."""

    # Default options
    opts = {
        # These must always be set
        '__debug':       True,
        '__debugfilter': '',
        'useragent':   'Mozilla/5.0 (Windows NT 6.1; rv:11.0) Gecko/20100101 Firefox/11.0',
        'fetchlinks':   True,   # Should we fetch links on the base domain?
        'pages':        20      # Number of google results pages to iterate
    }

    # Option descriptions
    optdescs = {
        'useragent': "User-Agent string to use when fetching Google pages.",
        'fetchlinks': "Fetch links found on the target domain-name?",
        'pages':    "Number of Google results pages to iterate through."
    }

    # URL this instance is working on
    seedUrl = None
    baseDomain = None # calculated from the URL in setup
    results = list()

    def setup(self, url, userOpts=dict()):
        global sf
        self.seedUrl = url
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # For error reporting, debug, etc.
        sf = SpiderFoot(self.opts)

         # Extract the 'meaningful' part of the FQDN from the URL
        self.baseDomain = sf.urlBaseDom(self.seedUrl)
        sf.debug('Base Domain: ' + self.baseDomain)

    # What events is this module interested in for input
    def watchedEvents(self):
        return None

    def start(self):
        # Sites hosted on the domain
        pages = sf.googleIterate("site:" + self.baseDomain, dict(limit=self.opts['pages']))
        for page in pages.keys():
            if page in self.results:
                continue

            # Check if we've been asked to stop
            if self.checkForStop():
                return None

            self.notifyListeners("WEBCONTENT", page, pages[page])
            self.results.append(page)

            # We can optionally fetch links to our domain found in the search
            # results. These may not have been identified through spidering.
            if self.opts['fetchlinks']:
                links = sf.parseLinks(page, pages[page])
                if len(links) == 0:
                    continue

                for link in links:
                    if link in self.results:
                        continue
                    sf.debug("Found a link: " + link)
                    baseDom = sf.urlBaseDom(link)
                    if baseDom == None:
                        continue
                    if baseDom.endswith(self.baseDomain):
                        if self.checkForStop():
                            return None
                        linkPage = sf.fetchUrl(link)
                        self.notifyListeners("URL", page, link)
                        self.notifyListeners("WEBCONTENT", link, linkPage['content'])
                        self.results.append(link)

# End of sfp_googlesearch class

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "You must specify a domain to start searching for."
        exit(-1)

    sfp = sfp_googlesearch(sys.argv[1])
    sfp.start()
