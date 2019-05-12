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
        'max_pages': 20
    }

    # Option descriptions
    optdescs = {
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
        return ['DOMAIN_NAME', 'EMAILADDR']

    def producedEvents(self):
        return ['DARKNET_MENTION_URL', 'DARKNET_MENTION_CONTENT', 'SEARCH_ENGINE_WEB_CONTENT']

    # https://darksearch.io/apidoc
    def query(self, qry, page):
        params = {
            'query': qry.encode('raw_unicode_escape'),
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

                if result.get('link') is not None:
                    evt = SpiderFootEvent("DARKNET_MENTION_URL", result.get('link'), self.__name__, event)
                    self.notifyListeners(evt)

                if result.get('title') is not None and result.get('description') is not None:
                    evt = SpiderFootEvent("DARKNET_MENTION_CONTENT",
                                          "Title: " + result.get('title') + "\n\n" + result.get('description'),
                                          self.__name__,
                                          event)
                    self.notifyListeners(evt)

            page += 1

# End of sfp_darksearch class
