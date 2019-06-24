# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_onionsearchengine
# Purpose:      Searches the Tor search engine onionsearchengine.com for content 
#               related to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     27/10/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
import re

class sfp_onionsearchengine(SpiderFootPlugin):
    """Onionsearchengine.com:Footprint,Investigate:Search Engines::Search Tor onionsearchengine.com for mentions of the target domain."""


    # Default options
    opts = {
        # We don't bother with pagination as ahmia seems fairly limited in coverage
        'fetchlinks': True,
        'blacklist': [ '.*://relate.*' ]
    }

    # Option descriptions
    optdescs = {
        'fetchlinks': "Fetch the darknet pages (via TOR, if enabled) to verify they mention your target.",
        'blacklist': "Exclude results from sites matching these patterns."
    }

    # Target
    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "HUMAN_NAME", "EMAILADDR"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DARKNET_MENTION_URL", "DARKNET_MENTION_CONTENT", "SEARCH_ENGINE_WEB_CONTENT"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            self.sf.debug("Already did a search for " + eventData + ", skipping.")
            return None
        else:
            self.results[eventData] = True


        keepGoing = True
        paging = ""
        pagenr = 1
        while keepGoing:
            # Sites hosted on the domain
            data = self.sf.fetchUrl("https://onionsearchengine.com/search.php?search=\"" + \
                                    eventData.replace(" ", "%20") + "\"&submit=Search" + paging, 
                                    useragent=self.opts['_useragent'], 
                                    timeout=self.opts['_fetchtimeout'])
            if data is None or not data.get('content'):
                self.sf.info("No results returned from onionsearchengine.com.")
                return None

            if "url.php?u=" not in data['content']:
                # Work around some kind of bug in the site
                if "you didn't submit a keyword" in data['content']:
                    pagenr += 1
                    paging = "&page=" + str(pagenr)
                    continue
                return None

            # Check if we've been asked to stop
            if self.checkForStop():
                return None

            if "forward >" in data['content']:
                pagenr += 1
                paging = "&page=" + str(pagenr)
            else:
                keepGoing = False

            # Submit the google results for analysis
            evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", data['content'],
                                  self.__name__, event)
            self.notifyListeners(evt)

            links = re.findall("url\.php\?u=(.[^\"\']+)[\"\']", 
                             data['content'], re.IGNORECASE | re.DOTALL)

            for link in links:
                if link in self.results:
                    continue
                else:
                    self.results[link] = True
                    blacklist = False
                    for r in self.opts['blacklist']:
                        if re.match(r, link, re.IGNORECASE):
                            self.sf.debug("Skipping " + link + " as it matches blacklist " + r)
                            blacklist = True
                    if blacklist:
                        continue

                    self.sf.debug("Found a darknet mention: " + link)
                    if self.sf.urlFQDN(link).endswith(".onion"):
                        if self.checkForStop():
                            return None
                        if self.opts['fetchlinks']:
                            res = self.sf.fetchUrl(link, timeout=self.opts['_fetchtimeout'],
                                                   useragent=self.opts['_useragent'])

                            if res['content'] is None:
                                self.sf.debug("Ignoring " + link + " as no data returned")
                                continue

                            if eventData not in res['content']:
                                self.sf.debug("Ignoring " + link + " as no mention of " + eventData)
                                continue
                            evt = SpiderFootEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                            self.notifyListeners(evt)

                            try:
                                startIndex = res['content'].index(eventData) - 120
                                endIndex = startIndex + len(eventData) + 240
                            except BaseException as e:
                                self.sf.debug("String not found in content.")
                                continue

                            data = res['content'][startIndex:endIndex]
                            evt = SpiderFootEvent("DARKNET_MENTION_CONTENT", "..." + data + "...",
                                                  self.__name__, evt)
                            self.notifyListeners(evt)

                        else:
                            evt = SpiderFootEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                            self.notifyListeners(evt)


# End of sfp_onionsearchengine class
