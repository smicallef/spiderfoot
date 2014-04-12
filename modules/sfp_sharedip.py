#-------------------------------------------------------------------------------
# Name:         sfp_sharedip
# Purpose:      Searches Bing and/or Robex.com for hosts sharing the same IP.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import random
import re
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_sharedip(SpiderFootPlugin):
    """Shared IP:Search Bing and/or Robex.com for hosts sharing the same IP."""

    # Default options
    opts = {
        'cohostsamedomain': False,
        'pages': 20,
    }

    # Option descriptions
    optdescs = {
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'pages': "If using Bing, how many pages to iterate through."
    }

    # Target
    baseDomain = None
    results = list()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ "IP_ADDRESS" ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "CO_HOSTED_SITE", "SEARCH_ENGINE_WEB_CONTENT" ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results.append(eventData)

        results = sf.bingIterate("ip:" + eventData, dict(limit=self.opts['pages'],
            useragent=self.opts['_useragent'], timeout=self.opts['_fetchtimeout']))
        myres = list()
        if results == None:
            sf.info("No data returned from Bing.")
            return None

        for key in results.keys():
            res = results[key]
            matches = re.findall("<div class=\"sb_meta\"><cite>(\S+)</cite>", 
                res, re.IGNORECASE)
            for match in matches:
                sf.info("Found something on same IP: " + match)
                site = sf.urlFQDN(match)
                if site not in myres and site != eventData:
                    if not self.opts['cohostsamedomain'] and site.endswith(self.baseDomain):
                        sf.debug("Skipping " + site + " because it is on the same domain.")
                        continue
                    evt = SpiderFootEvent("CO_HOSTED_SITE", site, self.__name__, event)
                    self.notifyListeners(evt)
                    myres.append(site)

            # Submit the bing results for analysis
            evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", results[key], 
                self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_sharedip class
