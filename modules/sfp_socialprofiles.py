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

import random
import re
import time
import urllib2
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

sites = {
    # Search string to use, domain name the profile will sit on within 
    # those search results.
    "Facebook": ['+title:%22{0}%22%20+site:facebook.com',
                 ['"(https?://[a-z\.]*facebook.[a-z\.]+/[^/\"<> ]+)"',
                 '(https?%3a%2f%2f[a-z\.]*facebook.[a-z\.]+%2f[^\/\"<> ]+)']],
    "Google+": ['+title:%22{0}%22%20+site:plus.google.com',
                ['"(https?://plus.google.[a-z\.]+/\d+[^\"<>\/ ]+)"',
                '(https?%3a%2f%2fplus.google.[a-z\.]+%2f\d+[^\/\"<> ]+)']],
    "LinkedIn": ['+title:%22{0}%22%20+site:linkedin.com',
                 ['"(https?://[a-z\.]*linkedin.[a-z\.]+/[^/\"<> ]+)"',
                 '(https?%3a%2f%2f[a-z\.]*linkedin.[a-z\.]+%2f[^\/\"<> ]+)']]
}


class sfp_socialprofiles(SpiderFootPlugin):
    """Social Media Profiles:Footprint,Passive:Social Media:slow,errorprone:Tries to discover the social media profiles for human names identified."""


    # Default options
    opts = {
        'pages': 1,
        'method': "bing",
        'tighten': True
    }

    # Option descriptions
    optdescs = {
        'pages': "Number of search engine pages of identified profiles to iterate through.",
        'tighten': "Tighten results by expecting to find the keyword of the target domain mentioned in the social media profile page results?",
        'method': "Search engine to use: google or bing."
    }

    keywords = None
    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.keywords = None

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["HUMAN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SOCIAL_MEDIA", "SEARCH_ENGINE_WEB_CONTENT"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if self.keywords is None:
            self.keywords = self.sf.domainKeywords(self.getTarget().getNames(),
                self.opts['_internettlds'])
            if len(self.keywords) == 0:
                self.keywords = None

        for site in sites:
            s = unicode(sites[site][0]).format(eventData)
            searchStr = s.replace(" ", "%20")
            results = None

            if self.opts['method'].lower() == "yahoo":
                self.sf.error("Yahoo is no longer supported. Please try 'bing' or 'google'.", False)
                return None

            if self.opts['method'].lower() == "google":
                results = self.sf.googleIterate(searchStr, dict(limit=self.opts['pages'],
                                                                useragent=self.opts['_useragent'],
                                                                timeout=self.opts['_fetchtimeout']))
                self.__dataSource__ = "Google"

            if self.opts['method'].lower() == "bing":
                results = self.sf.bingIterate(searchStr, dict(limit=self.opts['pages'],
                                                              useragent=self.opts['_useragent'],
                                                              timeout=self.opts['_fetchtimeout']))
                self.__dataSource__ = "Bing"

            if results is None:
                self.sf.info("No data returned from " + self.opts['method'] + ".")
                return None

            if self.checkForStop():
                return None

            for key in results:
                instances = list()

                for searchDom in sites[site][1]:
                    matches = re.findall(searchDom, results[key], re.IGNORECASE|re.MULTILINE)

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
                        if self.opts['tighten'] and self.keywords:
                            match = urllib2.unquote(match)
                            self.sf.debug("Tightening results to look for " + str(self.keywords))
                            pres = self.sf.fetchUrl(match, timeout=self.opts['_fetchtimeout'],
                                                    useragent=self.opts['_useragent'])

                            if pres['content'] is None:
                                continue
                            else:
                                found = False
                                for kw in self.keywords:
                                    if re.search("[^a-zA-Z\-\_]" + kw + "[^a-zA-Z\-\_]", 
                                                 pres['content'], re.IGNORECASE):
                                        found = True
                                if not found:
                                    continue

                        self.sf.info("Social Media Profile found at " + site + ": " + match)
                        match = urllib2.unquote(match)
                        evt = SpiderFootEvent("SOCIAL_MEDIA", site + ": " + match,
                                              self.__name__, event)
                        self.notifyListeners(evt)

                # Submit the results for analysis
                evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", results[key],
                                      self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_socialprofiles class
