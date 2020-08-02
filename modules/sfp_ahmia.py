# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ahmia
# Purpose:      Searches the Tor search engine 'Ahmia' for content related
#               to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/06/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
import re


class sfp_ahmia(SpiderFootPlugin):
    """Ahmia:Footprint,Investigate:Search Engines::Search Tor 'Ahmia' search engine for mentions of the target domain."""

    # Default options
    opts = {
        # We don't bother with pagination as ahmia seems fairly limited in coverage
        'fetchlinks': True,
        'fullnames': True
    }

    # Option descriptions
    optdescs = {
        'fetchlinks': "Fetch the darknet pages (via TOR, if enabled) to verify they mention your target.",
        'fullnames': "Search for human names?"
    }

    # Target
    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
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

        if not self.opts['fullnames'] and eventName == 'HUMAN_NAME':
            return None

        if eventData in self.results:
            self.sf.debug("Already did a search for " + eventData + ", skipping.")
            return None
        else:
            self.results[eventData] = True

        # Sites hosted on the domain
        data = self.sf.fetchUrl("https://ahmia.fi/search/?q=" + eventData.replace(" ", "%20"),
                                useragent=self.opts['_useragent'],
                                timeout=self.opts['_fetchtimeout'])
        if data is None or not data.get('content'):
            self.sf.info("No results returned from ahmia.fi.")
            return None

        if "redirect_url=" in data['content']:
            # Check if we've been asked to stop
            if self.checkForStop():
                return None

            links = re.findall("redirect_url=(.[^\"]+)\"",
                             data['content'], re.IGNORECASE | re.DOTALL)

            reported = False
            for link in links:
                if link in self.results:
                    continue
                else:
                    self.results[link] = True
                    self.sf.debug("Found a darknet mention: " + link)
                    if self.sf.urlFQDN(link).endswith(".onion"):
                        if self.checkForStop():
                            return None
                        if self.opts['fetchlinks']:
                            res = self.sf.fetchUrl(link, timeout=self.opts['_fetchtimeout'],
                                                   useragent=self.opts['_useragent'],
                                                   verify=False)

                            if res['content'] is None:
                                self.sf.debug("Ignoring " + link + " as no data returned")
                                continue

                            if eventData not in res['content']:
                                self.sf.debug("Ignoring " + link + " as no mention of " + eventData)
                                continue
                            evt = SpiderFootEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                            self.notifyListeners(evt)
                            reported = True

                            try:
                                startIndex = res['content'].index(eventData) - 120
                                endIndex = startIndex + len(eventData) + 240
                            except BaseException as e:
                                self.sf.debug("String not found in content.")
                                continue

                            wdata = res['content'][startIndex:endIndex]
                            evt = SpiderFootEvent("DARKNET_MENTION_CONTENT", "..." + wdata + "...",
                                                  self.__name__, evt)
                            self.notifyListeners(evt)
                            reported = True
                        else:
                            evt = SpiderFootEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                            self.notifyListeners(evt)
                            reported = True

            if reported:
                # Submit the search results for analysis
                evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", data['content'],
                                      self.__name__, event)
                self.notifyListeners(evt)


# End of sfp_ahmia class
