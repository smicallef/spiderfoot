# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_freegeoip
# Purpose:      SpiderFoot plug-in to identify the Geo-location of IP addresses
#               identified by other modules using freegeoip.net.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     18/02/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_freegeoip(SpiderFootPlugin):
    """FreeGeoIP:Footprint,Investigate,Passive:Real World::Identifies the physical location of IP addresses identified using freegeoip.net."""


    # Default options
    opts = {}
    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["GEOINFO"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        res = self.sf.fetchUrl("https://freegeoip.net/json/" + eventData,
                               timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
        if res['content'] is None:
            self.sf.info("No GeoIP info found for " + eventData)
        try:
            hostip = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        self.sf.info("Found GeoIP for " + eventData + ": " + hostip['country_name'])
        countrycity = hostip['country_name']

        evt = SpiderFootEvent("GEOINFO", countrycity, self.__name__, event)
        self.notifyListeners(evt)

        return None

# End of sfp_freegeoip class
