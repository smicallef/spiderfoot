#-------------------------------------------------------------------------------
# Name:         sfp_geoip
# Purpose:      SpiderFoot plug-in to identify the Geo-location of IP addresses
#               identified by other modules.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     18/02/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
import json
import socket
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_geoip(SpiderFootPlugin):
    """GeoIP:Identifies the physical location of IP addresses identified."""

    # Default options
    opts = { }

    # Target
    baseDomain = None
    results = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if self.results.has_key(eventData):
            sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        res = sf.fetchUrl("http://api.hostip.info/get_json.php?ip=" + eventData,
            timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
        if res['content'] == None:
            sf.info("No GeoIP info found for " + eventData)
        try:
            hostip = json.loads(res['content'])
        except Exception as e:
            sf.debug("Error processing JSON response.")
            return None

        sf.info("Found GeoIP for " + eventData + ": " + hostip['country_name'])
        countrycity = hostip['country_name']

        evt = SpiderFootEvent("GEOINFO", countrycity, self.__name__, event)
        self.notifyListeners(evt)

        return None

# End of sfp_geoip class
