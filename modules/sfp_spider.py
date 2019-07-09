# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_spider
# Purpose:      SpiderFoot plug-in for spidering sites and returning meta data
#               for other plug-ins to consume.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     25/03/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

import time
import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_spider(SpiderFootPlugin):
    """Spider:Footprint,Investigate:Crawling and Scanning:slow:Spidering of web-pages to extract content for searching."""


    # Default options
    opts = {
        'robotsonly': False,  # only follow links specified by robots.txt
        'pause': 1,  # number of seconds to pause between fetches
        'maxpages': 100,  # max number of pages to fetch
        'maxlevels': 3,  # max number of levels to traverse within a site
        'usecookies': True,  # Use cookies?
        'start': ['http://', 'https://'],
        'filterfiles': ['png', 'gif', 'jpg', 'jpeg', 'tiff', 'tif', 'tar',
                        'pdf', 'ico', 'flv', 'mp4', 'mp3', 'avi', 'mpg', 'gz',
                        'mpeg', 'iso', 'dat', 'mov', 'swf', 'rar', 'exe', 'zip',
                        'bin', 'bz2', 'xsl', 'doc', 'docx', 'ppt', 'pptx', 'xls',
                        'xlsx', 'csv'],
        'filtermime': ['image/'],
        'filterusers': True,  # Don't follow /~user directories
        'nosubs': False,  # Should links to subdomains be ignored?
        'reportduplicates': False,
        'parsetext': True
    }

    # Option descriptions
    optdescs = {
        'robotsonly': "Only follow links specified by robots.txt?",
        'pause': "Number of seconds to pause between fetches.",
        'usecookies': "Accept and use cookies?",
        'start': "Prepend targets with these until you get a hit, to start spidering.",
        'maxpages': "Maximum number of pages to fetch per starting point identified.",
        'maxlevels': "Maximum levels to traverse per starting point (e.g. hostname or link identified by another module) identified.",
        'filterfiles': "File extensions to ignore (don't fetch them.)",
        'filtermime': "MIME types to ignore.",
        'filterusers': "Skip spidering of /~user directories?",
        'nosubs': "Skip spidering of subdomains of the target?",
        'reportduplicates': "Report links every time one is found, even if found before?",
        'parsetext': "Parse content for possible hostnames/links, not just in valid HTML tags?"
    }

    # If using robots.txt, this will get populated with filter rules
    robotsRules = dict()

    # Pages already fetched
    fetchedPages = dict()

    # Events for links identified
    urlEvents = dict()

    # Tracked cookies per site
    siteCookies = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.fetchedPages = dict()
        self.urlEvents = dict()
        self.siteCookies = dict()
        self.__dataSource__ = "Target Website"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # Fetch data from a URL and obtain all links that should be followed
    def processUrl(self, url):
        site = self.sf.urlFQDN(url)
        cookies = None

        # Filter out certain file types (if user chooses to)
        checkExts = lambda ext: url.lower().split('?')[0].endswith('.' + ext.lower())
        if filter(checkExts, self.opts['filterfiles']):
            #self.sf.debug('Ignoring filtered extension: ' + link)
            return None

        if site in self.siteCookies:
            self.sf.debug("Restoring cookies for " + site + ": " + str(self.siteCookies[site]))
            cookies = self.siteCookies[site]
        # Fetch the contents of the supplied URL (object returned)
        fetched = self.sf.fetchUrl(url, False, cookies,
                                   self.opts['_fetchtimeout'], self.opts['_useragent'])
        self.fetchedPages[url] = True

        # Track cookies a site has sent, then send the back in subsquent requests
        if self.opts['usecookies'] and fetched['headers'] is not None:
            if fetched['headers'].get('Set-Cookie'):
                self.siteCookies[site] = fetched['headers'].get('Set-Cookie')
                self.sf.debug("Saving cookies for " + site + ": " + str(self.siteCookies[site]))

        if url not in self.urlEvents:
            self.sf.error("Something strange happened - shouldn't get here.", False)
            self.urlEvents[url] = None

        # Notify modules about the content obtained
        self.contentNotify(url, fetched, self.urlEvents[url])

        if fetched['realurl'] is not None and fetched['realurl'] != url:
            self.sf.debug("Redirect of " + url + " to " + fetched['realurl'])
            # Store the content for the redirect so that it isn't fetched again
            self.fetchedPages[fetched['realurl']] = True
            # Notify modules about the new link
            self.urlEvents[fetched['realurl']] = self.linkNotify(fetched['realurl'],
                                                                 self.urlEvents[url])
            url = fetched['realurl']  # override the URL if we had a redirect

        # Extract links from the content
        links = self.sf.parseLinks(url, fetched['content'], 
                                   self.getTarget().getNames(), 
                                   self.opts['parsetext'])

        if links is None or len(links) == 0:
            self.sf.info("No links found at " + url)
            return None

        # Notify modules about the links found
        # Aside from the first URL, this will be the first time a new
        # URL is spotted.
        for link in links:
            if not self.opts['reportduplicates']:
                if link in self.urlEvents:
                    continue
            # Supply the SpiderFootEvent of the parent URL as the parent
            self.urlEvents[link] = self.linkNotify(link, self.urlEvents[url])

        self.sf.debug('Links found from parsing: ' + str(links))
        return links

    # Clear out links that we don't want to follow
    def cleanLinks(self, links):
        returnLinks = dict()

        for link in links.keys():
            linkBase = self.sf.urlBaseUrl(link)
            linkFQDN = self.sf.urlFQDN(link)

            # Skip external sites (typical behaviour..)
            if not self.getTarget().matches(linkFQDN):
                #self.sf.debug('Ignoring external site: ' + link)
                continue

            # Optionally skip sub-domain sites
            if self.opts['nosubs'] and not \
                    self.getTarget().matches(linkFQDN, includeChildren=False):
                #self.sf.debug("Ignoring subdomain: " + link)
                continue

            # Skip parent domain sites
            if not self.getTarget().matches(linkFQDN, includeParents=False):
                #self.sf.debug("Ignoring parent domain: " + link)
                continue

            # Optionally skip user directories
            if self.opts['filterusers'] and '/~' in link:
                #self.sf.debug("Ignoring user folder: " + link)
                continue

            # If we are respecting robots.txt, filter those out too
            if linkBase in self.robotsRules and self.opts['robotsonly']:
                checkRobots = lambda blocked: type(blocked).lower(blocked) in link.lower() or blocked == '*'
                if filter(checkRobots, self.robotsRules[linkBase]):
                    #self.sf.debug("Ignoring page found in robots.txt: " + link)
                    continue

            # All tests passed, add link to be spidered
            self.sf.debug("Adding URL for spidering: " + link)
            returnLinks[link] = links[link]

        return returnLinks

    # Notify listening modules about links
    def linkNotify(self, url, parentEvent=None):
        if self.getTarget().matches(self.sf.urlFQDN(url)):
            utype = "LINKED_URL_INTERNAL"
        else:
            utype = "LINKED_URL_EXTERNAL"

        if type(url) != unicode:
            url = unicode(url, "utf-8", errors='replace')
        event = SpiderFootEvent(utype, url, self.__name__, parentEvent)
        self.notifyListeners(event)
        return event

    # Notify listening modules about raw data and others
    def contentNotify(self, url, httpresult, parentEvent=None):
        sendcontent = True
        if httpresult.get('headers'):
            ctype = httpresult['headers'].get('content-type')
            if not ctype:
                sendcontent = True
            else:
                for mt in self.opts['filtermime']:
                    if ctype.startswith(mt):
                        sendcontent = False

        if sendcontent:
            event = SpiderFootEvent("TARGET_WEB_CONTENT", httpresult['content'],
                                    self.__name__, parentEvent)
            self.notifyListeners(event)

        if httpresult.get('headers') != None:
            event = SpiderFootEvent("WEBSERVER_HTTPHEADERS", 
                                    json.dumps(httpresult['headers'], ensure_ascii=False),
                                    self.__name__, parentEvent)
            self.notifyListeners(event)

        event = SpiderFootEvent("HTTP_CODE", str(httpresult['code']),
                                self.__name__, parentEvent)
        self.notifyListeners(event)

        if not httpresult.get('headers'):
            return None

        ctype = httpresult['headers'].get('content-type')
        if ctype:
            event = SpiderFootEvent("TARGET_WEB_CONTENT_TYPE", ctype,
                                    self.__name__, parentEvent)
            self.notifyListeners(event)


    # Trigger spidering off the following events..
    # Spidering and search engines provide LINKED_URL_INTERNAL, and DNS lookups
    # provide INTERNET_NAME.
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL", "INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["WEBSERVER_HTTPHEADERS", "HTTP_CODE", "LINKED_URL_INTERNAL",
                "LINKED_URL_EXTERNAL", "TARGET_WEB_CONTENT",
                "TARGET_WEB_CONTENT_TYPE"]

    # Some other modules may request we spider things
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        spiderTarget = None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.urlEvents:
            self.sf.debug("Ignoring " + eventName + " as already spidered or is being spidered.")
            return None

        # Don't spider links we find ourselves, obviously
        if eventName == "LINKED_URL_INTERNAL" and "sfp_spider" in srcModuleName:
            self.sf.debug("Ignoring " + eventData + ", from self.")
            return None

        self.urlEvents[eventData] = event

        # Determine where to start spidering from if it's a INTERNET_NAME event
        if eventName == "INTERNET_NAME":
            for prefix in self.opts['start']:
                url = prefix + eventData
                res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])
                if res['content'] is not None:
                    spiderTarget = prefix + eventData
                    evt = SpiderFootEvent("LINKED_URL_INTERNAL", spiderTarget,
                                          self.__name__, event)
                    self.notifyListeners(evt)
                    break
        else:
            spiderTarget = eventData

        if spiderTarget is None:
            return None

        self.sf.info("Initiating spider of " + spiderTarget + " from " + srcModuleName)

        # Link the spidered URL to the event that triggered it
        self.urlEvents[spiderTarget] = event
        return self.spiderFrom(spiderTarget)

    # Start spidering
    def spiderFrom(self, startingPoint):
        keepSpidering = True
        totalFetched = 0
        levelsTraversed = 0
        nextLinks = dict()
        targetBase = self.sf.urlBaseUrl(startingPoint)

        # Are we respecting robots.txt?
        if self.opts['robotsonly'] and targetBase not in self.robotsRules:
            robotsTxt = self.sf.fetchUrl(targetBase + '/robots.txt',
                                         timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
            if robotsTxt['content'] is not None:
                self.sf.debug('robots.txt contents: ' + robotsTxt['content'])
                self.robotsRules[targetBase] = self.sf.parseRobotsTxt(robotsTxt['content'])

        if self.checkForStop():
            return None

        # First iteration we are starting with links found on the start page
        # Iterations after that are based on links found on those pages,
        # and so on..
        links = self.processUrl(startingPoint)  # fetch first page

        if links is None:
            self.sf.debug("No links found on the first fetch!")
            return None

        while keepSpidering:
            # Gets hit in the second and subsequent iterations when more links
            # are found
            if len(nextLinks) > 0:
                links = dict()

                # Fetch content from the new links
                for link in nextLinks.keys():
                    # Always skip links we've already fetched
                    if (link in self.fetchedPages):
                        self.sf.debug("Already fetched " + link + ", skipping.")
                        continue

                    # Check if we've been asked to stop
                    if self.checkForStop():
                        return None

                    self.sf.debug("Fetching fresh content from: " + link)
                    time.sleep(self.opts['pause'])
                    freshLinks = self.processUrl(link)
                    if freshLinks is not None:
                        links.update(freshLinks)

                    totalFetched += 1
                    if totalFetched >= self.opts['maxpages']:
                        self.sf.info("Maximum number of pages (" + str(self.opts['maxpages']) +
                                     ") reached.")
                        keepSpidering = False
                        break

            nextLinks = self.cleanLinks(links)
            self.sf.info("Found links: " + str(nextLinks))

            # We've scanned through another layer of the site
            levelsTraversed += 1
            self.sf.debug("At level: " + str(levelsTraversed) + ", Pages: " + str(totalFetched))
            if levelsTraversed >= self.opts['maxlevels']:
                self.sf.info("Maximum number of levels (" + str(self.opts['maxlevels']) +
                             ") reached.")
                keepSpidering = False

            # We've reached the end of our journey..
            if len(nextLinks) == 0:
                self.sf.info("No more links found to spider, finishing..")
                keepSpidering = False

            # We've been asked to stop scanning
            if self.checkForStop():
                keepSpidering = False

        return

# End of sfp_spider class
