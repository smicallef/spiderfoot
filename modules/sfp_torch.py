# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_torch
# Purpose:      Searches the Tor search engine 'TORCH' for content related
#               to the domain in question.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/06/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_torch(SpiderFootPlugin):

    meta = {
        'name': "TORCH",
        'summary': "Search Tor 'TORCH' search engine for mentions of the target domain.",
        'flags': ["errorprone", "tor"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://torchsearch.wordpress.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'description': "Torch or TorSearch is the best search engine "
                "for the hidden part of the internet. They're also the "
                "oldest and longest running search engine on Tor.\n"
                "Torch claims to have over one billion dark net pages indexed. "
                "They also don't censor search results or track what you "
                "search for.",
        }
    }

    opts = {
        'fetchlinks': True,
        'pages': 20,
        'fullnames': True
    }

    optdescs = {
        'fetchlinks': "Fetch the darknet pages (via TOR, if enabled) to verify they mention your target.",
        'pages': "Number of results pages to iterate through.",
        'fullnames': "Search for human names?"
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME", "HUMAN_NAME", "EMAILADDR"]

    def producedEvents(self):
        return ["DARKNET_MENTION_URL", "DARKNET_MENTION_CONTENT", "SEARCH_ENGINE_WEB_CONTENT"]

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        if not self.opts['fullnames'] and eventName == 'HUMAN_NAME':
            return

        if eventData in self.results:
            self.sf.debug("Already did a search for " + eventData + ", skipping.")
            return

        self.results[eventData] = True

        formpage = self.sf.fetchUrl(
            "http://xmh57jrzrnw6insl.onion",
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout']
        )

        if not formpage['content']:
            self.sf.info("Couldn't connect to TORCH, check that you have TOR enabled.")
            return

        # Need the form ID to submit later for the search
        m = re.findall(r"\<form method=\"get\" action=\"/(\S+)/search.cgi\"\>",
                       formpage['content'], re.IGNORECASE | re.DOTALL)
        if not m:
            return

        formid = m[0]

        pagecontent = ""
        pagecount = 0
        p = ""
        while "color=gray>next &gt;&gt;" not in pagecontent.lower() and pagecount < self.opts['pages']:
            # Check if we've been asked to stop
            if self.checkForStop():
                return

            if pagecount > 0:
                p = "&np=" + str(pagecount)
            pagecount += 1

            # Sites hosted on the domain
            data = self.sf.fetchUrl(
                f"http://xmh57jrzrnw6insl.onion/{formid}/search.cgi?q="
                + eventData.replace(" ", "%20") + "&cmd=Search!" + p,
                useragent=self.opts['_useragent'],
                timeout=self.opts['_fetchtimeout']
            )

            if data is None or not data.get('content'):
                self.sf.info("No results returned from TORCH.")
                return

            pagecontent = data['content']

            if "No documents were found" in data['content']:
                return

            # Submit the google results for analysis
            evt = SpiderFootEvent(
                "SEARCH_ENGINE_WEB_CONTENT",
                data['content'],
                self.__name__,
                event
            )
            self.notifyListeners(evt)

            links = re.findall(r"\<DT\>\d+.\s+<a href=\"(.*?)\"\s+TARGET=\"_blank\"\>",
                               data['content'], re.IGNORECASE | re.DOTALL)

            for link in links:
                if link in self.results:
                    continue

                self.results[link] = True
                self.sf.debug(f"Found a darknet mention: {link}")

                if self.sf.urlFQDN(link).endswith(".onion"):
                    if self.checkForStop():
                        return

                    if self.opts['fetchlinks']:
                        res = self.sf.fetchUrl(
                            link,
                            timeout=self.opts['_fetchtimeout'],
                            useragent=self.opts['_useragent'],
                            verify=False
                        )

                        if res['content'] is None:
                            self.sf.debug(f"Ignoring {link} as no data returned")
                            continue

                        if eventData not in res['content']:
                            self.sf.debug(f"Ignoring {link} as no mention of {eventData}")
                            continue

                        evt = SpiderFootEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                        self.notifyListeners(evt)

                        try:
                            startIndex = res['content'].index(eventData) - 120
                            endIndex = startIndex + len(eventData) + 240
                        except Exception:
                            self.sf.debug("String not found in content.")
                            continue

                        data = res['content'][startIndex:endIndex]
                        evt = SpiderFootEvent(
                            "DARKNET_MENTION_CONTENT", "..." + data + "...",
                            self.__name__,
                            evt
                        )
                        self.notifyListeners(evt)

                    else:
                        evt = SpiderFootEvent("DARKNET_MENTION_URL", link, self.__name__, event)
                        self.notifyListeners(evt)

# End of sfp_torch class
