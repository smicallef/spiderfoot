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
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootHelpers, SpiderFootPlugin


class sfp_spider(SpiderFootPlugin):

    meta = {
        'name': "Web Spider",
        'summary': "Spidering of web-pages to extract content for searching.",
        'flags': ["slow"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"]
    }

    # Default options
    opts = {
        'robotsonly': False,  # only follow links specified by robots.txt
        'pausesec': 0,  # number of seconds to pause between fetches
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
        'reportduplicates': False
    }

    # Option descriptions
    optdescs = {
        'robotsonly': "Only follow links specified by robots.txt?",
        'usecookies': "Accept and use cookies?",
        'pausesec': "Number of seconds to pause between page fetches.",
        'start': "Prepend targets with these until you get a hit, to start spidering.",
        'maxpages': "Maximum number of pages to fetch per starting point identified.",
        'maxlevels': "Maximum levels to traverse per starting point (e.g. hostname or link identified by another module) identified.",
        'filterfiles': "File extensions to ignore (don't fetch them.)",
        'filtermime': "MIME types to ignore.",
        'filterusers': "Skip spidering of /~user directories?",
        'nosubs': "Skip spidering of subdomains of the target?",
        'reportduplicates': "Report links every time one is found, even if found before?"
    }

    # If using robots.txt, this will get populated with filter rules
    robotsRules = dict()

    # Pages already fetched
    fetchedPages = None

    # Events for links identified
    urlEvents = None

    # Tracked cookies per site
    siteCookies = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.fetchedPages = self.tempStorage()
        self.urlEvents = self.tempStorage()
        self.siteCookies = self.tempStorage()
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # Search engines and DNS lookups provide INTERNET_NAME.
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL", "INTERNET_NAME"]

    # What events this module produces
    def producedEvents(self):
        return [
            "WEBSERVER_HTTPHEADERS",
            "HTTP_CODE",
            "LINKED_URL_INTERNAL",
            "LINKED_URL_EXTERNAL",
            "TARGET_WEB_CONTENT",
            "TARGET_WEB_CONTENT_TYPE"
        ]

    def processUrl(self, url: str) -> dict:
        """Fetch data from a URL and obtain all links that should be followed.

        Args:
            url (str): URL to fetch

        Returns:
            dict: links identified in URL content
        """
        site = self.sf.urlFQDN(url)
        cookies = None

        # Filter out certain file types (if user chooses to)
        if list(filter(lambda ext: url.lower().split('?')[0].endswith('.' + ext.lower()), self.opts['filterfiles'])):
            # self.debug(f"Ignoring URL with filtered file extension: {link}")
            return None

        if site in self.siteCookies:
            self.debug(f"Restoring cookies for {site}: {self.siteCookies[site]}")
            cookies = self.siteCookies[site]

        # Fetch the contents of the supplied URL
        fetched = self.sf.fetchUrl(
            url,
            cookies=cookies,
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
            sizeLimit=10000000,
            verify=False
        )
        self.fetchedPages[url] = True

        if not fetched:
            return None

        # Track cookies a site has sent, then send the back in subsquent requests
        if self.opts['usecookies'] and fetched['headers'] is not None:
            if fetched['headers'].get('Set-Cookie'):
                self.siteCookies[site] = fetched['headers'].get('Set-Cookie')
                self.debug(f"Saving cookies for {site}: {self.siteCookies[site]}")

        if url not in self.urlEvents:
            # TODO: be more descriptive
            self.error("Something strange happened - shouldn't get here: url not in self.urlEvents")
            self.urlEvents[url] = None

        # Notify modules about the content obtained
        self.contentNotify(url, fetched, self.urlEvents[url])

        real_url = fetched['realurl']
        if real_url and real_url != url:
            # self.debug(f"Redirect of {url} to {real_url}")
            # Store the content for the redirect so that it isn't fetched again
            self.fetchedPages[real_url] = True
            # Notify modules about the new link
            self.urlEvents[real_url] = self.linkNotify(real_url, self.urlEvents[url])
            url = real_url  # override the URL if we had a redirect

        data = fetched['content']

        if not data:
            return None

        if isinstance(data, bytes):
            data = data.decode('utf-8', errors='replace')

        # Extract links from the content
        links = SpiderFootHelpers.extractLinksFromHtml(
            url,
            data,
            self.getTarget().getNames()
        )

        if not links:
            self.debug(f"No links found at {url}")
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

        self.debug(f"Links found from parsing: {links.keys()}")
        return links

    def cleanLinks(self, links: list) -> list:
        """Clear out links that we don't want to follow.

        Args:
            links (list): links

        Returns:
            list: links suitable for spidering
        """
        returnLinks = dict()

        for link in links:
            linkBase = SpiderFootHelpers.urlBaseUrl(link)
            linkFQDN = self.sf.urlFQDN(link)

            # Skip external sites (typical behaviour..)
            if not self.getTarget().matches(linkFQDN):
                # self.debug('Ignoring external site: ' + link)
                continue

            # Optionally skip sub-domain sites
            if self.opts['nosubs'] and not \
                    self.getTarget().matches(linkFQDN, includeChildren=False):
                # self.debug("Ignoring subdomain: " + link)
                continue

            # Skip parent domain sites
            if not self.getTarget().matches(linkFQDN, includeParents=False):
                # self.debug("Ignoring parent domain: " + link)
                continue

            # Optionally skip user directories
            if self.opts['filterusers'] and '/~' in link:
                # self.debug("Ignoring user folder: " + link)
                continue

            # If we are respecting robots.txt, filter those out too
            if linkBase in self.robotsRules and self.opts['robotsonly']:
                if list(filter(lambda blocked: type(blocked).lower(blocked) in link.lower() or blocked == '*', self.robotsRules[linkBase])):
                    # self.debug("Ignoring page found in robots.txt: " + link)
                    continue

            # All tests passed, add link to be spidered
            self.debug(f"Adding URL for spidering: {link}")
            returnLinks[link] = links[link]

        return list(returnLinks.keys())

    # Notify listening modules about links
    def linkNotify(self, url: str, parentEvent=None):
        if self.getTarget().matches(self.sf.urlFQDN(url)):
            utype = "LINKED_URL_INTERNAL"
        else:
            utype = "LINKED_URL_EXTERNAL"

        if type(url) != str:
            url = str(url, "utf-8", errors='replace')
        event = SpiderFootEvent(utype, url, self.__name__, parentEvent)
        self.notifyListeners(event)
        return event

    # Notify listening modules about raw data and others
    def contentNotify(self, url: str, httpresult: dict, parentEvent=None) -> None:
        if not isinstance(httpresult, dict):
            return

        event = SpiderFootEvent(
            "HTTP_CODE",
            str(httpresult['code']),
            self.__name__,
            parentEvent
        )
        event.actualSource = url
        self.notifyListeners(event)

        store_content = True
        headers = httpresult.get('headers')

        if headers:
            event = SpiderFootEvent(
                "WEBSERVER_HTTPHEADERS",
                json.dumps(headers, ensure_ascii=False),
                self.__name__,
                parentEvent
            )
            event.actualSource = url
            self.notifyListeners(event)

            ctype = headers.get('content-type')
            if ctype:
                for mt in self.opts['filtermime']:
                    if ctype.startswith(mt):
                        store_content = False

                event = SpiderFootEvent(
                    "TARGET_WEB_CONTENT_TYPE",
                    ctype.replace(" ", "").lower(),
                    self.__name__,
                    parentEvent
                )
                event.actualSource = url
                self.notifyListeners(event)

        if store_content:
            content = httpresult.get('content')
            if content:
                event = SpiderFootEvent(
                    "TARGET_WEB_CONTENT",
                    str(content),
                    self.__name__,
                    parentEvent
                )
                event.actualSource = url
                self.notifyListeners(event)

    def handleEvent(self, event) -> None:
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        spiderTarget = None

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Don't spider links we find ourselves
        if srcModuleName == "sfp_spider":
            self.debug(f"Ignoring {eventName}, from self.")
            return None

        if eventData in self.urlEvents:
            self.debug(f"Ignoring {eventData} as already spidered or is being spidered.")
            return None

        self.urlEvents[eventData] = event

        # Determine where to start spidering from if it's a INTERNET_NAME event
        if eventName == "INTERNET_NAME":
            for prefix in self.opts['start']:
                res = self.sf.fetchUrl(
                    prefix + eventData,
                    timeout=self.opts['_fetchtimeout'],
                    useragent=self.opts['_useragent'],
                    verify=False
                )

                if not res:
                    continue

                if res['content'] is not None:
                    spiderTarget = prefix + eventData
                    evt = SpiderFootEvent(
                        "LINKED_URL_INTERNAL",
                        spiderTarget,
                        self.__name__,
                        event
                    )
                    self.notifyListeners(evt)
                    break
        else:
            spiderTarget = eventData

        if not spiderTarget:
            self.info(f"No reply from {eventData}, aborting.")
            return None

        self.debug(f"Initiating spider of {spiderTarget} from {srcModuleName}")

        # Link the spidered URL to the event that triggered it
        self.urlEvents[spiderTarget] = event
        return self.spiderFrom(spiderTarget)

    def spiderFrom(self, startingPoint: str) -> None:
        pagesFetched = 0
        levelsTraversed = 0

        # Are we respecting robots.txt?
        if self.opts['robotsonly']:
            targetBase = SpiderFootHelpers.urlBaseUrl(startingPoint)
            if targetBase not in self.robotsRules:
                res = self.sf.fetchUrl(
                    targetBase + '/robots.txt',
                    timeout=self.opts['_fetchtimeout'],
                    useragent=self.opts['_useragent'],
                    verify=False
                )
                if res:
                    robots_txt = res['content']
                    if robots_txt:
                        self.debug(f"robots.txt contents: {robots_txt}")
                        self.robotsRules[targetBase] = SpiderFootHelpers.extractUrlsFromRobotsTxt(robots_txt)

        # First iteration we are starting with the target link.
        nextLinks = [startingPoint]

        # Iterations after that are based on links found on those pages, while:
        # number of spidered pages < max pages
        # spidering depth <= max levels (the first level is the first link)
        while (pagesFetched < self.opts['maxpages']) and (levelsTraversed <= self.opts['maxlevels']):
            if not nextLinks:
                self.info("No more links to spider, finishing.")
                return

            # Fetch content from the new links
            links = dict()
            for link in nextLinks:
                if self.checkForStop():
                    return

                if link in self.fetchedPages:
                    self.debug(f"Already fetched {link}, skipping.")
                    continue

                self.debug(f"Fetching fresh content from: {link}")

                time.sleep(self.opts['pausesec'])

                freshLinks = self.processUrl(link)
                if freshLinks:
                    links.update(freshLinks)

                pagesFetched += 1
                if pagesFetched >= self.opts['maxpages']:
                    self.info(f"Maximum number of pages ({self.opts['maxpages']}) reached.")
                    return

            nextLinks = self.cleanLinks(links)
            self.debug(f"Found links: {nextLinks}")

            # We've scanned through another layer of the site
            levelsTraversed += 1
            self.debug(f"At level: {levelsTraversed}, Pages: {pagesFetched}")
            if levelsTraversed > self.opts['maxlevels']:
                self.info(f"Maximum number of levels ({self.opts['maxlevels']}) reached.")

# End of sfp_spider class
