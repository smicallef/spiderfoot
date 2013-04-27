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
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in __init__)
sf = None

class sfp_spider(SpiderFootPlugin):
    """ Spidering of web-pages to extract content for searching. Probably the most important module. """

    # Default options
    opts = {
        'robotsonly':   False, # only follow links specified by robots.txt
        'pause':        1, # number of seconds to pause between fetches
        'maxpages':     1000, # max number of pages to fetch
        'maxlevels':    5, # max number of levels to traverse within a site
        'usecookies':   True, # Use cookies?
        'start':        [ 'http://', 'https://' ],
        'filterfiles':  ['png','gif','jpg','jpeg','tiff', 'tif', 'js', 'css',
                        'pdf','tif','ico','flv', 'mp4', 'mp3', 'avi', 'mpg',
                        'mpeg', 'iso', 'dat', 'mov', 'swf'], # Extensions to not fetch
        'filterusers':  True, # Don't follow /~user directories
        'noexternal':   True, # Should links to external sites be ignored? (**dangerous if False**)
        'nosubs':       False, # Should links to subdomains be ignored?
    }

    # Option descriptions
    optdescs = {
        'robotsonly':   "Only follow links specified by robots.txt?",
        'pause':        "Number of seconds to pause between fetches.",
        'usecookies':   "Accept and use cookies?",
        'start':        "Prepend targets with these until you get a hit, to start spidering.",
        'maxpages':     "Maximum number of pages to fetch per target identified.",
        'maxlevels':    "Maximum levels to traverse per target identified.",
        'filterfiles':  "File extensions to ignore (don't fetch them.)",
        'filterusers':  "Skip spidering of /~user directories?",
        'noexternal':   "Skip spidering of external sites? (**dangerous if False**)",
        'nosubs':       "Skip spidering of subdomains of the target?"
    }

    # If using robots.txt, this will get populated with filter rules
    robotsRules = dict()

    # Target
    baseDomain = None

    # Pages already fetched
    fetchedPages = dict()

    # Events for links identified
    urlEvents = dict()

    # Tracked cookies per site
    siteCookies = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.fetchedPages = dict()
        self.urlEvents = dict()
        self.siteCookies = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # Fetch data from a URL and obtain all links that should be followed
    def processUrl(self, url):
        site = sf.urlFQDN(url)
        cookies = None
        if self.siteCookies.has_key(site):
            sf.debug("Restoring cookies for " + site + ": " + str(self.siteCookies[site]))
            cookies = self.siteCookies[site]
        # Fetch the contents of the supplied URL (object returned)
        fetched = sf.fetchUrl(url, False, cookies)
        self.fetchedPages[url] = True

        # Track cookies a site has sent, then send the back in subsquent requests
        if self.opts['usecookies'] and fetched['headers'] != None:
            if fetched['headers'].get('Set-Cookie'):
                self.siteCookies[site] = fetched['headers'].get('Set-Cookie')
                sf.debug("Saving cookies for " + site + ": " + str(self.siteCookies[site]))

        if not self.urlEvents.has_key(url):
            self.urlEvents[url] = None

        # Notify modules about the content obtained
        self.contentNotify(url, fetched, self.urlEvents[url])

        if fetched['realurl'] != None and fetched['realurl'] != url:
            sf.debug("Redirect of " + url + " to " + fetched['realurl'])
            # Store the content for the redirect so that it isn't fetched again
            self.fetchedPages[fetched['realurl']] = True
            # Notify modules about the new link
            self.urlEvents[fetched['realurl']] = self.linkNotify(fetched['realurl'], 
                self.urlEvents[url])
            url = fetched['realurl'] # override the URL if we had a redirect

        # Extract links from the content
        links = sf.parseLinks(url, fetched['content'], self.baseDomain)

        if links == None or len(links) == 0:
            sf.info("No links found at " + url)
            return None

        # Notify modules about the links found
        # Aside from the first URL, this will be the first time a new
        # URL is spotted.
        for link in links:
            # Supply the SpiderFootEvent of the parent URL as the parent
            self.urlEvents[link] = self.linkNotify(link, self.urlEvents[url])

        sf.debug('Links found from parsing: ' + str(links))
        return links

    # Clear out links that we don't want to follow
    def cleanLinks(self, links):
        returnLinks = dict()

        for link in links.keys():
            linkBase = sf.urlBaseUrl(link)

            # Optionally skip external sites (typical behaviour..)
            if self.opts['noexternal'] and not sf.urlBaseUrl(link).endswith(self.baseDomain):
                sf.debug('Ignoring external site: ' + link)
                continue

            # Optionally skip sub-domain sites
            if self.opts['nosubs'] and not sf.urlBaseUrl(link).endswith('://' + self.baseDomain):
                sf.debug("Ignoring subdomain: " + link)
                continue

            # Optionally skip user directories
            if self.opts['filterusers'] and '/~' in link:
                sf.debug("Ignoring user folder: " + link)
                continue

            # If we are respecting robots.txt, filter those out too
            checkRobots = lambda blocked: str.lower(blocked) in str.lower(str(link)) or blocked == '*'
            if self.opts['robotsonly'] and filter(checkRobots, self.robotsRules[linkBase]):
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

    # Notify listening modules about links
    def linkNotify(self, url, parentEvent=None):
        if sf.urlBaseUrl(url).endswith(self.baseDomain):
            type = "LINKED_URL_INTERNAL"
        else:
            type = "LINKED_URL_EXTERNAL"

        event = SpiderFootEvent(type, url, self.__name__, parentEvent)
        self.notifyListeners(event)

        return event

    # Notify listening modules about raw data and others
    def contentNotify(self, url, httpresult, parentEvent=None):
        event = SpiderFootEvent("RAW_DATA", httpresult['content'], 
            self.__name__, parentEvent)
        self.notifyListeners(event)

        event = SpiderFootEvent("WEBSERVER_HTTPHEADERS", httpresult['headers'],
            self.__name__, parentEvent)
        self.notifyListeners(event)

        event = SpiderFootEvent("HTTP_CODE", str(httpresult['code']),
            self.__name__, parentEvent)
        self.notifyListeners(event)

    # Trigger spidering off the following events..
    # Google search provides LINKED_URL_INTERNAL, and DNS lookups
    # provide SUBDOMAIN.
    def watchedEvents(self):
        return [ "LINKED_URL_INTERNAL", "SUBDOMAIN" ]

    # Some other modules may request we spider things
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        spiderTarget = None

        # Ignore self-generated events so that we don't end up in a recursive loop
        if "sfp_spider" in srcModuleName:
            sf.debug("Ignoring event from myself.")
            return None

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.urlEvents.keys():
            sf.debug("Ignoring " + eventData + " as already spidered or is being spidered.")           
            return None
        else:
            self.urlEvents[eventData] = event

        # Determine where to start spidering from if it's a SUBDOMAIN event
        if eventName == "SUBDOMAIN":
            for prefix in self.opts['start']:
                res = sf.fetchUrl(prefix + eventData)
                if res['content'] != None:
                    spiderTarget = prefix + eventData
                    break
        else:
            spiderTarget = eventData

        if spiderTarget == None:
            return None

        sf.info("Initiating spider of " + spiderTarget)

        # Link the spidered URL to the event that triggered it
        self.urlEvents[spiderTarget] = event
        return self.spiderFrom(spiderTarget)

    # Start spidering
    def spiderFrom(self, startingPoint):
        keepSpidering = True
        totalFetched = 0
        levelsTraversed = 0
        nextLinks = dict()
        targetBase = sf.urlBaseUrl(startingPoint)

        # Are we respecting robots.txt?
        if self.opts['robotsonly'] and not self.robotsRules.has_key(targetBase):
            robotsTxt = sf.fetchUrl(targetBase + '/robots.txt')
            if robotsTxt['content'] != None:
                sf.debug('robots.txt contents: ' + robotsTxt['content'])
                self.robotsRules[targetBase] = sf.parseRobotsTxt(robotsTxt['content'])
            else:
                sf.error("Unable to fetch robots.txt and you've asked to abide by its contents.")
                return None

        # First iteration we are starting with links found on the start page
        # Iterations after that are based on links found on those pages,
        # and so on..
        links = self.processUrl(startingPoint)  # fetch first page

        # No links from the first fetch means we've got a problem
        if links == None:
            sf.error("No links found on the first fetch!", exception=False)
            return

        while keepSpidering:
            # Gets hit in the second and subsequent iterations when more links
            # are found
            if len(nextLinks) > 0:
                links = dict()

                # Fetch content from the new links
                for link in nextLinks.keys():
                    # Always skip links we've already fetched
                    if (link in self.fetchedPages.keys()):
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
                        sf.info("Maximum number of pages (" + str(self.opts['maxpages']) + \
                            ") reached.")
                        keepSpidering = False
                        break

            nextLinks = self.cleanLinks(links)
            sf.info("Found links: " + str(nextLinks))

            # We've scanned through another layer of the site
            levelsTraversed += 1
            sf.info("Now at traversal level: " + str(levelsTraversed))
            if levelsTraversed >= self.opts['maxlevels']:
                sf.info("Maximum number of levels (" + str(self.opts['maxlevels']) + \
                    ") reached.")
                keepSpidering = False

            # We've reached the end of our journey..
            if len(nextLinks) == 0:
                sf.info("No more links found to spider, finishing..")
                keepSpidering = False

            # We've been asked to stop scanning
            if self.checkForStop():
                keepSpidering = False

        return
# End of sfp_spider class
