# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ipinfo
# Purpose:     SpiderFoot plug-in to identify the Geo-location of IP addresses
#              identified by other modules using ipinfo.io.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     17/06/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_ipinfo(SpiderFootPlugin):
    """IPInfo.io:Footprint,Investigate,Passive:Real World:apikey:Identifies the physical location of IP addresses identified using ipinfo.io."""

    # Default options
    opts = { 
        "api_key": "" 
    }
    optdescs = {
        "api_key": "Ipinfo.io access token."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'IPV6_ADDRESS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["GEOINFO"]

    # https://ipinfo.io/developers
    def queryIP(self, ip):
        headers = {
            'Authorization': "Bearer " + self.opts['api_key']
        }
        res = self.sf.fetchUrl("https://ipinfo.io/" + ip + "/json",
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'],
                               headers=headers)

        if res['code'] == "429":
            self.sf.error("You are being rate-limited by ipinfo.io.", False)
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.info("No GeoIP info found for " + ip)
            return None

        try:
            result = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        return result

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_ipinfo but did not set an API key!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        self.results[eventData] = True

        data = self.queryIP(eventData)

        if data is None:
            return None

        if 'country' not in data:
            return None

        location = ', '.join(filter(None, [data.get('city'), data.get('region'), data.get('country')]))
        self.sf.info("Found GeoIP for " + eventData + ": " + location)

        evt = SpiderFootEvent("GEOINFO", location, self.__name__, event)
        self.notifyListeners(evt)

        return None

# End of sfp_ipinfo class
