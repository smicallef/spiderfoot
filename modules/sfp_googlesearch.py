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
import random
import re
import time
from sflib import SpiderFoot, SpiderFootPlugin

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_googlesearch(SpiderFootPlugin):
    """Some light Google scraping to identify links for spidering."""

    # Default options
    opts = {
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

    # Scrape Google for content, starting at startUrl and iterating through
    # results based on options supplied. Will return a dictionary of all pages
    # fetched and their contents {page => content}.
    # Options accepted:
    # limit: number of search result pages before returning, default is 10
    # nopause: don't randomly pause between fetches
    def googleIterate(self, searchString, opts=dict()):
        limit = 10
        fetches = 0
        returnResults = dict()

        if opts.has_key('limit'):
            limit = opts['limit']

        # We attempt to make the URL look as authentically human as possible
        seedUrl = "http://www.google.com/search?q={0}".format(searchString) + \
            "&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:en-US:official&client=firefox-a"
        firstPage = sf.fetchUrl(seedUrl)
        if firstPage['code'] == "403":
            sf.error("Google doesn't like us right now..")
            return None

        if firstPage['content'] == None:
            sf.error("Failed to fetch content from Google.")
            return None

        returnResults[seedUrl] = firstPage['content']

        matches = re.findall("(\/search\S+start=\d+.[^\'\"]*sa=N)", firstPage['content'])
        while matches > 0 and fetches < limit:
            nextUrl = None
            fetches += 1
            for match in matches:
                # Google moves in increments of 10
                if "start=" + str(fetches*10) in match:
                    nextUrl = match.replace("&amp;", "&")

            if nextUrl == None:
                sf.debug("Nothing left to scan for in Google results.")
                return returnResults
            sf.info("Next Google URL: " + nextUrl)

            # Wait for a random number of seconds between fetches
            if not opts.has_key('nopause'):
                pauseSecs = random.randint(4, 15)
                sf.info("Pausing for " + str(pauseSecs))
                time.sleep(pauseSecs)

            # Check if we've been asked to stop
            if self.checkForStop():
                return None

            nextPage = sf.fetchUrl('http://www.google.com' + nextUrl)
            if firstPage['code'] == 403:
                sf.error("Google doesn't like us any more..")
                return returnResults

            if nextPage['content'] == None:
                sf.error("Failed to fetch subsequent content from Google.")
                return returnResults

            returnResults[nextUrl] = nextPage['content']
            matches = re.findall("(\/search\S+start=\d+.[^\'\"]*)", nextPage['content'], re.IGNORECASE)

        return returnResults

    def start(self):
        # Sites hosted on the domain
        pages = self.googleIterate("site:" + self.baseDomain, dict(limit=self.opts['pages']))
        if pages == None:
            sf.info("No results returned from Google.")
            return None

        for page in pages.keys():
            if page in self.results:
                continue

            # Check if we've been asked to stop
            if self.checkForStop():
                return None

            # Submit the google results for analysis
            self.notifyListeners("WEBCONTENT", page, pages[page])
            self.results.append(page)

            # We can optionally fetch links to our domain found in the search
            # results. These may not have been identified through spidering.
            if self.opts['fetchlinks']:
                links = sf.parseLinks(page, pages[page], self.baseDomain)
                if len(links) == 0:
                    continue

                for link in links:
                    if link in self.results:
                        continue
                    sf.info("Found a link: " + link)
                    if sf.urlBaseUrl(link).endswith(self.baseDomain):
                        if self.checkForStop():
                            return None
                        linkPage = sf.fetchUrl(link)

                        # Submit info from what we've fetched for analysis
                        self.notifyListeners("URL_INTERNAL", page, link)
                        self.notifyListeners("WEBCONTENT", link, linkPage['content'])
                        self.notifyListeners("HTTP_CODE", link, linkPage['code'])
                        self.notifyListeners("WEBSERVER_HTTPHEADERS", link, linkPage['headers'])
                        self.results.append(link)

# End of sfp_googlesearch class

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "You must specify a domain to start searching for."
        exit(-1)

    sfp = sfp_googlesearch(sys.argv[1])
    sfp.start()
