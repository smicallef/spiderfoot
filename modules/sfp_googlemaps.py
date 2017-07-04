# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_googlemaps
# Purpose:      SpiderFoot plug-in to identify historical certificates for a domain
#               from googlemaps.sh, and from this identify hostnames.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     18/03/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_googlemaps(SpiderFootPlugin):
    """Google Maps:Footprint,Investigate,Passive:Real World::Identifies potential physical addresses and latitude/longitude coordinates."""


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
        return ['DOMAIN_NAME', 'PHYSICAL_ADDRESS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["PHYSICAL_ADDRESS", "PHYSICAL_COORDINATES"]

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

        res = self.sf.fetchUrl("https://maps.googleapis.com/maps/api/geocode/json?address=" + \
                               eventData, timeout=self.opts['_fetchtimeout'], 
                               useragent=self.opts['_useragent'])
        if res['content'] is None:
            self.sf.info("No location info found for " + eventData)
            return None

        evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", res['content'], 
                              self.__name__, event)
        self.notifyListeners(evt)

        try:
            data = json.loads(res['content'])['results'][0]

            if eventName in ["PHYSICAL_ADDRESS", "DOMAIN_NAME"] and \
               srcModuleName != "sfp_googlemaps":
                if 'geometry' in data:
                        lat = str(data['geometry']['location']['lat'])
                        lng = str(data['geometry']['location']['lng'])
                        evt = SpiderFootEvent("PHYSICAL_COORDINATES", lat + "," + lng, 
                                              self.__name__, event)
                        self.notifyListeners(evt)

            if 'formatted_address' in data:
                evt = SpiderFootEvent("PHYSICAL_ADDRESS", data['formatted_address'], 
                                      self.__name__, event)
                self.notifyListeners(evt)
        except Exception as e:
            self.sf.debug("Error processing JSON response: " + str(e))
            return None

        return None

# End of sfp_googlemaps class
