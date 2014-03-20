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
        return [ "SEARCH_ENGINE_WEB_CONTENT" ]

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
        firstPage = sf.fetchUrl(seedUrl, timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'])
        if firstPage['code'] == "403":
            sf.error("Google doesn't like us right now..", False)
            return None

        if firstPage['content'] == None:
            sf.error("Failed to fetch content from Google for PasteBin.")
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
                sf.debug("Nothing left to scan for in Google PasteBin results.")
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

            nextPage = sf.fetchUrl('http://www.google.com' + nextUrl,
                timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
            if firstPage['code'] == 403:
                sf.error("Google doesn't like us any more..", False)
                return returnResults

            if nextPage['content'] == None:
                sf.error("Failed to fetch subsequent content from Google PasteBin search.")
                return returnResults

            returnResults[nextUrl] = nextPage['content']
            matches = re.findall("(\/search\S+start=\d+.[^\'\"]*)", nextPage['content'], re.IGNORECASE)

        return returnResults

    def start(self):
        # Sites hosted on the domain
        pages = self.googleIterate("site:pastebin.com+\"" + \
            self.baseDomain + "\"", dict(limit=self.opts['pages']))
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
            links = sf.parseLinks(page, pages[page], self.baseDomain)
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

                    evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT",
                        res['content'], self.__name__)
                    self.notifyListeners(evt)

# End of sfp_pastebin class
