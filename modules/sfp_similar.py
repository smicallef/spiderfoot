#-------------------------------------------------------------------------------
# Name:         sfp_similar
# Purpose:      SpiderFoot plug-in for identifying domains that look similar
#               to the one being queried.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
import time
import random
from sflib import SpiderFoot, SpiderFootPlugin

# These are all string builders, {0} = the domain keyword, {1} = the page number

# Domaintools.com:
# Seems to be the best choice overall
domtoolUrlLeft = "http://www.domaintools.com/buy/domain-search/?q={0}&bc=25&bn=y&bh=A&order=left&pool=A&filter=y&search_type=&rows=100&de_search=Search&page={1}"
domtoolUrlRight = "http://www.domaintools.com/buy/domain-search/?q={0}&bc=25&bn=y&bh=A&order=right&pool=A&filter=y&search_type=&rows=100&de_search=Search&page={1}"
domtoolLastPageIndicator = "&gt;&gt;"
domtoolIncrement = 100

# Namedroppers.org:
# Downside is that a maximum of 500 results are returned
namedropUrlLeft = "http://www.namedroppers.org/b/q?p={1}&k={0}&min=1&max=63&order=0&display=0&first=1&adv=1&com=1&net=1&org=1&edu=1&biz=1&us=1&info=1&name=1"
namedropUrlRight = "http://www.namedroppers.org/b/q?p={1}&k={0}&min=1&max=63&order=0&display=0&last=1&adv=1&com=1&net=1&org=1&edu=1&biz=1&us=1&info=1&name=1"
namedropLastPageIndicator = "&gt;&gt;"

# Whois.com:
# Downside is that this doesn't allow startswith/endswith searching
whoisUrlFirst = "http://www.whois.net/domain-keyword-search/{0}"
whoisUrlN = "http://www.whois.net/domain-keyword-search/{0}/{1}"
whoisLastPageIndicator = "Next >"
whoisIncrement = 16

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_similar(SpiderFootPlugin):
    """Search various sources to identify similar looking domain names."""

    # Default options
    opts = {
        # Domaintools will 403 you without a browser-like useragent
        'useragent':   'Mozilla/5.0 (Windows NT 6.1; rv:11.0) Gecko/20100101 Firefox/11.0',
        'source':       'ALL', # domaintools, namedroppers or ALL
        'method':       'left,right', # left and/or right (doesn't apply to whois.com)
        'activeonly':   False # Only report domains that have content (try to fetch the page)
    }

    # Option descriptions
    optdescs = {
        'useragent':   "User-Agent string to use when fetching pages from providers.",
        'source':       "Provider to use: 'domaintools', 'namedroppers' or 'ALL'.",
        'method':       "Pattern search method to use: 'left,right', 'left' or 'right'.",
        'activeonly':   "Only report domains that have content (try to fetch the page)?"
    }

    # Internal results tracking
    results = list()

    # Target
    baseDomain = None

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def findDomains(self, keyword, content):
        matches = re.findall("([a-z0-9\-]*" + keyword + "[a-z0-9\-]*\.[a-z]+)", 
            content, re.IGNORECASE)

        return matches

    # What events is this module interested in for input
    def watchedEvents(self):
        return None

    # Fetch and loop through Whois.com results, updating our results data. Stop
    # once we've reached the end.
    def scrapeWhois(self, keyword):
        reachedEnd = False
        i = 0
        while not reachedEnd:
            if i == 0:
                # First iteration
                fetchPage = whoisUrlFirst.format(keyword)
            else:
                # Subsequent iterations have a different URL (in chunks of 16)
                fetchPage = whoisUrlN.format(keyword, i * whoisIncrement)

            # Check if we've been asked to stop
            if self.checkForStop():
                return None

            whois = sf.fetchUrl(fetchPage)
            if whois['content'] == None:
                return None

            # Extract the similar domains out of the whois content
            freshResults = self.findDomains(keyword, whois['content'])
            for result in freshResults:
                if result in self.results:
                    continue

                self.storeResult(fetchPage, result)

            if not whoisLastPageIndicator in whois['content']:
                reachedEnd = True
            else:
                time.sleep(random.randint(1, 10))

            i += 1

    def scrapeDomaintools(self, keyword, position):
        reachedEnd = False
        i = 1 # Using 0 will cause the first page to appear twice
        while not reachedEnd:
            if position == "LEFT":
                fetchPage = domtoolUrlLeft.format(keyword, i)
            else:
                fetchPage = domtoolUrlRight.format(keyword, i)

            if self.checkForStop():
                return None

            domtool = sf.fetchUrl(fetchPage)
            if domtool['content'] == None:
                return None

            # Extract the similar domains out of the domain tools content
            freshResults = self.findDomains(keyword, domtool['content'])
            for result in freshResults:
                if result in self.results:
                    continue
                # Images for the domain get picked up by the regexp
                if '.jpg' in result:
                    continue

                self.storeResult(fetchPage, result)

            if not domtoolLastPageIndicator in domtool['content']:
                reachedEnd = True
            else:
                time.sleep(random.randint(1, 10))

            i += 1

    def scrapeNamedroppers(self, keyword, position):
        reachedEnd = False
        i = 1 # Using 0 will cause the first page to appear twice
        while not reachedEnd:
            if position == "LEFT":
                fetchPage = namedropUrlLeft.format(keyword, i)
            else:
                fetchPage = namedropUrlRight.format(keyword, i)

            if self.checkForStop():
                return None

            namedrop = sf.fetchUrl(fetchPage)
            if namedrop['content'] == None:
                return None

            # Extract the similar domains out of the namedropper content
            freshResults = self.findDomains(keyword, namedrop['content'])
            for result in freshResults:
                if result in self.results:
                    continue

                self.storeResult(fetchPage, result)

            if not namedropLastPageIndicator in namedrop['content']:
                reachedEnd = True
            else:
                time.sleep(random.randint(1, 10))

            i += 1

    # Store the result internally and notify listening modules
    def storeResult(self, source, result):
        sf.info("Found a similar domain: " + result)
        self.results.append(result)

        # Inform listening modules
        if self.opts['activeonly']:
            if self.checkForStop():
                return None

            pageContent = sf.fetchUrl('http://' + result)
            if pageContent['content'] != None:
                self.notifyListeners("SIMILARDOMAIN", source, result)
        else:
            self.notifyListeners("SIMILARDOMAIN", source, result)


    # Search for similar sounding domains
    def start(self):
        keyword = sf.domainKeyword(self.baseDomain)
        sf.debug("Keyword extracted from " + self.baseDomain + ": " + keyword)

        # No longer seems to work.
        #if "whois" in self.opts['source'] or "ALL" in self.opts['source']:
        #    self.scrapeWhois(keyword)

        if "domtools" in self.opts['source'] or "ALL" in self.opts['source']:
            if "left" in self.opts['method']:
                self.scrapeDomaintools(keyword, "LEFT")
            if "right" in self.opts['method']:
                self.scrapeDomaintools(keyword, "RIGHT")

        if "namedroppers" in self.opts['source'] or "ALL" in self.opts['source']:
            if "left" in self.opts['method']:
                self.scrapeNamedroppers(keyword, "LEFT")
            if "right" in self.opts['method']:
                self.scrapeNamedroppers(keyword, "RIGHT")

        return None

# End of sfp_similar class

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "You must supply a URL as a starting point."
        exit(-1)

    sfp = sfp_similar(sys.argv[1])
    sfp.start()
