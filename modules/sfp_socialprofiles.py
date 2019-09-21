# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_socialprofiles
# Purpose:      Tries to discover social media profiles of any identified human names.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import urllib2
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

sites = {
    # Search string to use, domain name the profile will sit on within
    # those search results.
    "Facebook": [
        "\"{name}\"+site:facebook.com",
        [
            '[ \'"](https?://[a-z\.]*facebook.[a-z\.]+/[^/"\'<> ]+/?)[\'" ]',
            '(https?%3a%2f%2f[a-z\.]*facebook.[a-z\.]+%2f[^\/"\'<> ]+/?)',
        ],
    ],
    "Google+": [
        "\"{name}\"+site:plus.google.com",
        [
            '[ \'"](https?://plus.google.[a-z\.]+/\d+[^"\'<>\/ ]+)[\'" ]',
            '(https?%3a%2f%2fplus.google.[a-z\.]+%2f\d+[^\/"\'<> ]+)',
        ],
    ],
    "LinkedIn": [
        "\"{name}\"+site:linkedin.com",
        [
            '["\' ](https?://[a-z\.]*linkedin.[a-z\.]+/[^\?"\'<> ]+)[\'" ]',
            '(https?%3a%2f%2f[a-z\.]*linkedin.[a-z\.]+%2f[^\?"\'<> ]+)',
        ],
    ],
}


class sfp_socialprofiles(SpiderFootPlugin):
    """Social Media Profiles:Footprint,Passive:Social Media:slow,apikey:Tries to discover the social media profiles for human names identified."""

    # Default options
    opts = {
        "count": 20,
        "method": "bing",
        "tighten": True,
        "bing_api_key": "",
        "google_api_key": "",
        "google_cse_id": "013611106330597893267:tfgl3wxdtbp",
    }

    # Option descriptions
    optdescs = {
        "count": "Number of bing search engine results of identified profiles to iterate through.",
        "method": "Search engine to use: 'google' or 'bing'.",
        "tighten": "Tighten results by expecting to find the keyword of the target domain mentioned in the social media profile page results?",
        "bing_api_key": "Bing API Key for social media profile search.",
        "google_api_key": "Google API Key for social media profile search.",
        "google_cse_id": "Google Custom Search Engine ID.",
    }

    keywords = None
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.keywords = None
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["HUMAN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SOCIAL_MEDIA", "RAW_RIR_DATA"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['google_api_key'] == "" and self.opts['bing_api_key'] == "":
            self.sf.error("You enabled sfp_socialprofiles but did not set a Google or Bing API key!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if self.keywords is None:
            self.keywords = self.sf.domainKeywords(
                self.getTarget().getNames(), self.opts["_internettlds"]
            )
            if len(self.keywords) == 0:
                self.keywords = None

        for site in sites:
            s = unicode(sites[site][0]).format(name=eventData)
            searchStr = s.replace(" ", "%20")
            res = None

            if self.opts["method"].lower() == "yahoo":
                self.sf.error(
                    "Yahoo is no longer supported. Please try 'bing' or 'google'.",
                    False,
                )
                return None

            if self.opts["method"].lower() == "google":
                res = self.sf.googleIterate(
                    searchString=searchStr,
                    opts={
                        "timeout": self.opts["_fetchtimeout"],
                        "useragent": self.opts["_useragent"],
                        "api_key": self.opts["google_api_key"],
                        "cse_id": self.opts["google_cse_id"],
                    },
                )
                self.__dataSource__ = "Google"

            if self.opts["method"].lower() == "bing":
                res = self.sf.bingIterate(
                    searchString=searchStr,
                    opts={
                        "timeout": self.opts["_fetchtimeout"],
                        "useragent": self.opts["_useragent"],
                        "count": self.opts["count"],
                        "api_key": self.opts["bing_api_key"],
                    },
                )
                self.__dataSource__ = "Bing"

            if res is None:
                self.sf.info("No data returned from " + self.opts["method"] + ".")
                continue

            if self.checkForStop():
                return None

            # Submit the results for analysis
            evt = SpiderFootEvent(
                "RAW_RIR_DATA", str(res), self.__name__, event
            )
            self.notifyListeners(evt)

            instances = list()
            for searchDom in sites[site][1]:
                # Search both the urls & the search engine web content
                search_string = " ".join(res["urls"] + [str(res)])

                matches = re.findall(
                    searchDom, search_string, re.IGNORECASE | re.MULTILINE
                )

                if not matches:
                    continue

                for match in matches:
                    self.sf.debug("Match found: " + match)
                    if match in instances:
                        continue
                    else:
                        instances.append(match)

                    if self.checkForStop():
                        return None

                    # Fetch the profile page if we are checking
                    # for a firm relationship.
                    # Keywords might be empty if the target was an IP, subnet or name.
                    if self.opts["tighten"] and self.keywords:
                        match = urllib2.unquote(match)
                        self.sf.debug(
                            "Tightening results to look for " + str(self.keywords)
                        )
                        pres = self.sf.fetchUrl(
                            match,
                            timeout=self.opts["_fetchtimeout"],
                            useragent=self.opts["_useragent"],
                        )

                        if pres["content"] is None:
                            continue
                        else:
                            found = False
                            for kw in self.keywords:
                                if re.search(
                                    "[^a-zA-Z\-\_]" + kw + "[^a-zA-Z\-\_]",
                                    pres["content"],
                                    re.IGNORECASE,
                                ):
                                    found = True
                            if not found:
                                continue

                    self.sf.info("Social Media Profile found at " + site + ": " + match)
                    match = urllib2.unquote(match)
                    evt = SpiderFootEvent(
                        "SOCIAL_MEDIA", site + ": " + match, self.__name__, event
                    )
                    self.notifyListeners(evt)


# End of sfp_socialprofiles class
