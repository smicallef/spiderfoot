# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_socialprofiles
# Purpose:      Obtains social media profiles of any identified human names.
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
import urllib
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

sites = {
    # Search string to use, domain name the profile will sit on within 
    # those search results.
    "Facebook": ['+title:%22{0}%22%20+site:facebook.com',
                 '"(https?://[a-z\.]*facebook.[a-z\.]+/[^\"<> ]+)"'],
    "Google+": ['+title:%22{0}%22%20+site:plus.google.com',
                '"(https?://plus.google.[a-z\.]+/\d+[^\"<>\/ ]+)"'],
    "LinkedIn": ['+title:%22{0}%22%20+site:linkedin.com',
                 '"(https?://[a-z\.]*linkedin.[a-z\.]+/[^\"<> ]+)"']
}


class sfp_socialprofiles(SpiderFootPlugin):
    """Social Media Profiles:Footprint,Passive:Social Media:errorprone:Identify the social media profiles for human names identified."""


    # Default options
    opts = {
        'pages': 1,
        'method': "yahoo",
        'tighten': True
    }

    # Option descriptions
    optdescs = {
        'pages': "Number of search engine pages of identified profiles to iterate through.",
        'tighten': "Tighten results by expecting to find the keyword of the target domain mentioned in the social media profile page results?",
        'method': "Search engine to use: google, yahoo or bing."
    }

    keywords = None
    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

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
            self.results.append(eventData)

        if self.keywords is None:
            self.keywords = self.sf.domainKeywords(self.getTarget().getNames(),
                self.opts['_internettlds'])

        for site in sites.keys():
            s = unicode(sites[site][0]).format(eventData)
            searchStr = s.replace(" ", "%20")
            searchDom = sites[site][1]
            results = None

            if self.opts['method'].lower() == "google":
                results = self.sf.googleIterate(searchStr, dict(limit=self.opts['pages'],
                                                                useragent=self.opts['_useragent'],
                                                                timeout=self.opts['_fetchtimeout']))
                self.__dataSource__ = "Google"

            if self.opts['method'].lower() == "yahoo":
                results = self.sf.yahooIterate(searchStr, dict(limit=self.opts['pages'],
                                                               useragent=self.opts['_useragent'],
                                                               timeout=self.opts['_fetchtimeout']))
                self.__dataSource__ = "Yahoo"

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

            pauseSecs = random.randint(4, 15)
            self.sf.debug("Pausing for " + str(pauseSecs))
            time.sleep(pauseSecs)

            for key in results.keys():
                instances = list()

                matches = re.findall(searchDom, results[key], re.IGNORECASE)

                if matches is not None:
                    for match in matches:
                        if match in instances:
                            continue
                        else:
                            instances.append(match)

                        if self.opts['method'] == "yahoo":
                            match = re.sub(r'.*RU=(.*?)/RK=.*', r'\1', match)

                        if self.checkForStop():
                            return None

                        # Fetch the profile page if we are checking
                        # for a firm relationship.
                        if self.opts['tighten']:
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
                        evt = SpiderFootEvent("SOCIAL_MEDIA", site + ": " + match,
                                              self.__name__, event)
                        self.notifyListeners(evt)

                # Submit the results for analysis
                evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", results[key],
                                      self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_socialprofiles class
