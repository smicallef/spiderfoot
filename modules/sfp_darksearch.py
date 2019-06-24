# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_darksearch
# Purpose:      Searches the Darksearch.io Tor search engine for content related
#               to the domain in question.
#
# Author:      <bcoles[at]gmail[.]com>
#
# Created:     2019-05-11
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_darksearch(SpiderFootPlugin):
    """Darksearch:Footprint,Investigate:Search Engines::Search the Darksearch.io Tor search engine for mentions of the target domain."""

    # Default options
    opts = {
        'fetchlinks': True,
        'max_pages': 20
    }

    # Option descriptions
    optdescs = {
        'fetchlinks': "Fetch the darknet pages (via TOR, if enabled) to verify they mention your target.",
        'max_pages': "Maximum number of pages of results to fetch."
    }

    results = dict()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "Darksearch"
        self.results = dict()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['DOMAIN_NAME', 'HUMAN_NAME', 'EMAILADDR']

    def producedEvents(self):
        return ['DARKNET_MENTION_URL', 'DARKNET_MENTION_CONTENT', 'SEARCH_ENGINE_WEB_CONTENT']

    # https://darksearch.io/apidoc
    def query(self, qry, page):
        params = {
            'query': '"' + qry.encode('raw_unicode_escape') + '"',
            'page': str(page)
        }

        res = self.sf.fetchUrl("https://darksearch.io/api/search?" + urllib.urlencode(params),
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        # Usage policy mandates maximum 30 requests per minute
        time.sleep(2)

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug("Error processing JSON response: " + str(e))
            return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        page = 1
        pages = self.opts['max_pages']
        while page <= pages:
            res = self.query(eventData, page)

            if res is None:
                return None

            page += 1

            last_page = res.get('last_page')

            if last_page is None:
                pages = 0

            if last_page < pages:
                pages = last_page

            data = res.get('data')

            if data is None:
                return None

            for result in data:
                if result is None:
                    continue

                evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", str(result), self.__name__, event)
                self.notifyListeners(evt)

                link = result.get('link')

                if link is None:
                    continue

                if link in self.results:
                    continue

                if not self.sf.urlFQDN(link).endswith(".onion"):
                    continue

                self.results[link] = True
                self.sf.debug("Found a darknet mention: " + link)

                if self.opts['fetchlinks']:
                    res = self.sf.fetchUrl(link,
                                           timeout=self.opts['_fetchtimeout'],
                                           useragent=self.opts['_useragent'])

                    if res['content'] is None:
                        self.sf.debug("Ignoring " + link + " as no data returned")
                        continue

                    if eventData not in res['content']:
                        self.sf.debug("Ignoring " + link + " as no mention of " + eventData)
                        continue

                    evt = SpiderFootEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                    self.notifyListeners(evt)

                    # extract content excerpt
                    try:
                        startIndex = res['content'].index(eventData) - 120
                        endIndex = startIndex + len(eventData) + 240
                    except BaseException as e:
                        self.sf.debug("String not found in content.")
                        continue

                    data = res['content'][startIndex:endIndex]
                    evt = SpiderFootEvent("DARKNET_MENTION_CONTENT",
                                          "..." + data + "...",
                                          self.__name__,
                                          event)
                    self.notifyListeners(evt)

                else:
                    evt = SpiderFootEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                    self.notifyListeners(evt)

                    if result.get('title') is None and result.get('description') is None:
                        self.sf.debug("Ignoring " + link + " as no mention of " + eventData)
                        continue

                    evt = SpiderFootEvent("DARKNET_MENTION_CONTENT",
                                          "Title: " + result.get('title') + "\n\n" +
                                          "..." + result.get('description') + "...",
                                          self.__name__,
                                          event)
                    self.notifyListeners(evt)

# End of sfp_darksearch class
