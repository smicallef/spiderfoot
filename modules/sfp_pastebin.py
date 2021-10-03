# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_pastebin
# Purpose:      Searches Google for PasteBin content related to the domain in
#               question.
#
# Author:      Steve Micallef <steve@binarypool.com> and ShellCodeNoobx
#
# Created:     20/03/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_pastebin(SpiderFootPlugin):

    meta = {
        'name': "PasteBin",
        'summary': "PasteBin search (via Google Search API) to identify related content.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://pastebin.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://pastebin.com/doc_api",
                "https://pastebin.com/faq"
            ],
            'apiKeyInstructions': [
                "Visit https://developers.google.com/custom-search/v1/introduction",
                "Register a free Google account",
                "Click on 'Get A Key'",
                "Connect a Project",
                "The API Key will be listed under 'YOUR API KEY'"
            ],
            'favIcon': "https://pastebin.com/favicon.ico",
            'logo': "https://pastebin.com/favicon.ico",
            'description': "Pastebin is a website where you can store any text online for easy sharing. "
            "The website is mainly used by programmers to store pieces of source code or "
            "configuration information, but anyone is more than welcome to paste any type of text. "
            "The idea behind the site is to make it more convenient for people to share large amounts of text online.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "cse_id": "013611106330597893267:tfgl3wxdtbp"
    }

    # Option descriptions
    optdescs = {
        "api_key": "Google API Key for PasteBin search.",
        "cse_id": "Google Custom Search Engine ID.",
    }

    domains = {
        'pastebin': "pastebin.com"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME", "EMAILADDR"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["LEAKSITE_CONTENT", "LEAKSITE_URL"]

    def handleEvent(self, event):
        eventData = event.data

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error(f"You enabled {self.__class__.__name__} but did not set a Google API key!")
            self.errorState = True
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        for dom in list(self.domains.keys()):
            target = self.domains[dom]
            res = self.sf.googleIterate(
                searchString=f'+site:{target} "{eventData}"',
                opts={
                    "timeout": self.opts["_fetchtimeout"],
                    "useragent": self.opts["_useragent"],
                    "api_key": self.opts["api_key"],
                    "cse_id": self.opts["cse_id"],
                },
            )

            if res is None:
                # Failed to talk to the Google API or no results returned
                return

            urls = res["urls"]
            new_links = list(set(urls) - set(self.results.keys()))

            # Add new links to results
            for link in new_links:
                self.results[link] = True

            relevant_links = [
                link for link in new_links if self.sf.urlBaseUrl(link).endswith(target)
            ]

            for link in relevant_links:
                self.debug("Found a link: " + link)

                if self.checkForStop():
                    return

                res = self.sf.fetchUrl(link, timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.debug(f"Ignoring {link} as no data returned")
                    continue

                if re.search(
                    r"[^a-zA-Z\-\_0-9]" + re.escape(eventData) + r"[^a-zA-Z\-\_0-9]",
                    res['content'],
                    re.IGNORECASE
                ) is None:
                    continue

                evt1 = SpiderFootEvent("LEAKSITE_URL", link, self.__name__, event)
                self.notifyListeners(evt1)

                evt2 = SpiderFootEvent("LEAKSITE_CONTENT", res['content'], self.__name__, evt1)
                self.notifyListeners(evt2)

# End of sfp_pastebin class
