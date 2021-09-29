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
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_darksearch(SpiderFootPlugin):

    meta = {
        'name': "Darksearch",
        'summary': "Search the Darksearch.io Tor search engine for mentions of the target domain.",
        'flags': ["tor"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://darksearch.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://darksearch.io/apidoc",
                "https://darksearch.io/dorks"
            ],
            'favIcon': "https://darksearch.io/favicons/favicon-64.png",
            'logo': "https://darksearch.io/images/darksearch-logo-02.svg?366834f96a6d3988f0f11f99dba27bf4",
            'description': "The 1st real Dark Web search engine.\n"
            "Our DarkWeb search engine is completely free.\n"
            "Access the results directly, without the need to install Tor.\n"
            "Our API is available for free to automate your research.",
        }
    }

    # Default options
    opts = {
        'fetchlinks': True,
        'max_pages': 20,
        'fullnames': True
    }

    # Option descriptions
    optdescs = {
        'fetchlinks': "Fetch the darknet pages (via TOR, if enabled) to verify they mention your target.",
        'max_pages': "Maximum number of pages of results to fetch.",
        'fullnames': "Search for human names?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['DOMAIN_NAME', 'HUMAN_NAME', 'EMAILADDR']

    def producedEvents(self):
        return ['DARKNET_MENTION_URL', 'DARKNET_MENTION_CONTENT', 'RAW_RIR_DATA']

    # https://darksearch.io/apidoc
    def query(self, qry, page):
        params = {
            'query': '"' + qry.encode('raw_unicode_escape').decode("ascii", errors='replace') + '"',
            'page': str(page)
        }

        res = self.sf.fetchUrl("https://darksearch.io/api/search?" + urllib.parse.urlencode(params),
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        # Usage policy mandates maximum 30 requests per minute
        time.sleep(2)

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if not self.opts['fullnames'] and eventName == 'HUMAN_NAME':
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        page = 1
        pages = self.opts['max_pages']
        while page <= pages:
            found = False

            if self.checkForStop():
                return

            query_results = self.query(eventData, page)

            if query_results is None:
                return

            page += 1

            last_page = query_results.get('last_page')

            if last_page is None:
                pages = 0

            if last_page < pages:
                pages = last_page

            data = query_results.get('data')

            if data is None:
                return

            for result in data:
                if result is None:
                    continue

                link = result.get('link')

                if link is None:
                    continue

                if link in self.results:
                    continue

                if not self.sf.urlFQDN(link).endswith(".onion"):
                    continue

                self.results[link] = True
                self.debug("Found a darknet mention: " + link)

                if self.opts['fetchlinks']:
                    res = self.sf.fetchUrl(link,
                                           timeout=self.opts['_fetchtimeout'],
                                           useragent=self.opts['_useragent'],
                                           verify=False)

                    if res['content'] is None:
                        self.debug("Ignoring " + link + " as no data returned")
                        continue

                    if eventData not in res['content']:
                        self.debug("Ignoring " + link + " as no mention of " + eventData)
                        continue

                    evt = SpiderFootEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                    self.notifyListeners(evt)
                    found = True

                    # extract content excerpt
                    try:
                        startIndex = res['content'].index(eventData) - 120
                        endIndex = startIndex + len(eventData) + 240
                    except Exception:
                        self.debug("String not found in content.")
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
                    found = True

                    if result.get('title') is None and result.get('description') is None:
                        self.debug("Ignoring " + link + " as no mention of " + eventData)
                        continue

                    evt = SpiderFootEvent("DARKNET_MENTION_CONTENT",
                                          "Title: " + result.get('title') + "\n\n"
                                          + "..." + result.get('description') + "...",
                                          self.__name__,
                                          event)
                    self.notifyListeners(evt)

            if found:
                evt = SpiderFootEvent("RAW_RIR_DATA", str(query_results), self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_darksearch class
