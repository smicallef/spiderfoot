#-------------------------------------------------------------------------------
# Name:         sfp_spider
# Purpose:      SpiderFoot plug-in for spidering sites and returning meta data
#               for other plug-ins to consume.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     25/03/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
import time
from sflib import SpiderFoot, SpiderFootPlugin

# SpiderFoot standard lib (must be initialized in __init__)
sf = None

class sfp_spider(SpiderFootPlugin):
    """ Spidering of web-pages to extract content for searching. Probably the most important module. """

    # Default options
    opts = {
        # These must always be set
        '_debug':       True,
        '_debugfilter': '',
        # options specific to this module
        'robotsonly':   False, # only follow links specified by robots.txt
        'pause':        0, # number of seconds to pause between fetches
        'maxpages':     10000, # max number of pages to fetch
        'maxlevels':    10, # max number of levels to traverse within a site
        'filterfiles':  ['png','gif','jpg','jpeg','tiff', 'tif', 'js', 'css',
                        'pdf','tif','ico','flv', 'mp4', 'mp3', 'avi', 'mpg',
                        'mpeg', 'iso', 'dat', 'mov'], # Extensions to not fetch
        'filterusers':  True, # Don't follow /~user directories
        'noexternal':   True, # Should links to external sites be ignored? (**dangerous if False**)
        'nosubs':       False # Should links to subdomains be ignored?
    }

    # If using robots.txt, this will get populated with filter rules
    robotsRules = dict()

    # URL this instance is working on
    seedUrl = None
    baseDomain = None # calculated from the URL in __init__

    # Results of spidering. This is a dictionary with the URL as the key, and
    # each value is again a dictionary of the following key=value pairs:
    #   source:     the link where the link was found
    #   original:   what the link looked like in the content it was found in
    #   fetched:    has the content been fetched (True/False)
    # >> Not all of these will be populated at the same time <<
    results = dict()

    def setup(self, url, userOpts=dict()):
        global sf
        self.seedUrl = url
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # For error reporting, debug, etc.
        sf = SpiderFoot(self.opts)

        if '://' not in self.seedUrl:
            sf.fatal("Please specify a full URL starting point, prefixed with http:// or https://")

        if re.match('.*\d+\.\d+\.\d+\.\d+.*', self.seedUrl):
            sf.fatal("Need a named URL to start with, not an IP.")

        # Extract the 'meaningful' part of the FQDN from the URL
        self.baseDomain = sf.urlBaseDom(self.seedUrl)
        sf.debug('Base Domain: ' + self.baseDomain)

        # Are we respecting robots.txt?
        if self.opts['robotsonly']:
            robotsTxt = sf.fetchUrl(sf.urlBaseUrl(self.seedUrl) + '/robots.txt').read()
            if robotsTxt['content'] != None:
                sf.debug('robots.txt contents: ' + robotsTxt['content'])
                self.robotsRules = sf.parseRobotsTxt(robotsTxt['content'])

    # This module listens to no events
    def watchedEvents(self):
        return None

    # Add a set of results to the results dictionary
    def storeResult(self, url, source=None, original=None, httpresult=None):
        stored = '' # just used for debugging

        # Store in memory for use within this module and notify listeners
        if url not in self.results.keys():
            self.results[url] = dict()

        if source != None:
            self.results[url]['source'] = source
            self.notifyListeners("URL", source, url)
            stored += 's'

        if original != None:
            self.results[url]['original'] = original
            stored += 'o'

        if httpresult != None:
            if httpresult.has_key('content'):
                self.notifyListeners("WEBCONTENT", url, httpresult['content'])

            self.notifyListeners("WEBSERVER_HTTPHEADERS", url, httpresult['headers'])

            self.results[url]['fetched'] = True
            stored += 'h'

        # Heavy debug
        #sf.debug("Results stored for " + url + ": " + str(self.results[url]))
        # Basic debug
        sf.debug('stored result (elements:' + stored + '): ' + url)

        # Eventually store to a database..
        return None

    # Fetch data from a URL and obtain all links that should be followed
    def processUrl(self, url):
        # Fetch the contents of the supplied URL (object returned)
        fetched = sf.fetchUrl(url)
        if fetched['realurl'] != None and fetched['realurl'] != url:
            sf.debug("Redirect of " + url + " to " + fetched['realurl'])
            # Store the content for the redirect so that it isn't fetched again
            self.storeResult(url, None, None, fetched)
            url = fetched['realurl'] # override the URL if we had a redirect

        # Store the content just received
        self.storeResult(url, None, None, fetched)

        # Extract links from the content
        links = sf.parseLinks(url, fetched['content'])

        if links == None or len(links) == 0:
            sf.debug("No links found at " + url)
            return None

        #sf.debug('Links found from parsing: ' + str(links))
        return links

    # Clear out links that we don't want to follow
    def cleanLinks(self, links):
        returnLinks = dict()

        for link in links.keys():
            # Optionally skip external sites
            if self.opts['noexternal'] and self.baseDomain != sf.urlBaseDom(link):
                sf.debug('Ignoring external site: ' + link)
                continue

            # Optionally skip sub-domain sites
            if self.opts['nosubs'] and sf.urlBaseUrl(self.seedUrl) not in link:
                sf.debug("Ignoring subdomain: " + link)
                continue

            # Optionally skip user directories
            if self.opts['filterusers'] and '/~' in link:
                sf.debug("Ignoring user folder: " + link)
                continue

            # If we are respecting robots.txt, filter those out too
            checkRobots = lambda blocked: str.lower(blocked) in str.lower(str(link)) or blocked == '*'
            if self.opts['robotsonly'] and filter(checkRobots, self.robotsRules):
                sf.debug("Ignoring page found in robots.txt: " + link)
                continue

            # Filter out certain file types (if user chooses to)
            checkExts = lambda ext: '.' + str.lower(ext) in str.lower(str(link))
            if filter(checkExts, self.opts['filterfiles']):
                sf.debug('Ignoring filtered extension: ' + link)
                continue

            # All tests passed, add link to be spidered
            sf.debug("Adding URL for spidering: " + link)
            returnLinks[link] = links[link]

        return returnLinks

    # Spidering is performed here
    def start(self):
        # ~*~ Start spidering! ~*~
        # First iteration we are starting with links found on the start page
        # Iterations after that are based on links found on those pages,
        # and so on..
        keepSpidering = True
        links = self.processUrl(self.seedUrl)  # fetch first page
        totalFetched = 0
        levelsTraversed = 0
        nextLinks = dict()

        # No links from the first fetch means we've got a problem
        if links == None:
            sf.error("No links found on the first fetch!")
            return

        while keepSpidering:
            # Gets hit in the second and subsequent iterations when more links
            # are found
            if len(nextLinks) > 0:
                links = dict()

                # Fetch content from the new links
                for link in nextLinks.keys():
                    # Always skip links we've already fetched
                    if (link in self.results.keys() and self.results[link].has_key('fetched')):
                        if self.results[link]['fetched']:
                            sf.debug("Already fetched " + link + ", skipping.")
                            continue

                    # Check if we've been asked to stop
                    if self.checkForStop():
                        return None

                    sf.debug("Fetching fresh content from: " + link)
                    time.sleep(self.opts['pause'])
                    freshLinks = self.processUrl(link)
                    if freshLinks != None:
                        links.update(freshLinks)

                    totalFetched += 1
                    if totalFetched >= self.opts['maxpages']:
                        sf.debug("Maximum number of pages (" + str(self.opts['maxpages']) + \
                            ") reached.")
                        keepSpidering = False
                        break

            # Clear out the rubbish/ignored links from our list of links
            nextLinks = self.cleanLinks(links)

            # Record the result, for all links (not just those fetched)
            for link in links.keys():
                self.storeResult(link, links[link]['source'], links[link]['original'])

            # We've scanned through another layer of the site
            levelsTraversed += 1
            sf.debug("Now at traversal level: " + str(levelsTraversed))
            if levelsTraversed >= self.opts['maxlevels']:
                sf.debug("Maximum number of levels (" + str(self.opts['maxlevels']) + \
                    ") reached.")
                keepSpidering = False

            # We've reached the end of our journey..
            if len(nextLinks) == 0:
                sf.debug("No more links found to spider, finishing..")
                keepSpidering = False

            # We've been asked to stop scanning
            if self.checkForStop():
                keepSpidering = False

        return
# End of sfp_spider class

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "You must specify a URL to start spidering from."
        exit(-1)

    spider = sfp_spider(sys.argv[1])
    spider.start()

