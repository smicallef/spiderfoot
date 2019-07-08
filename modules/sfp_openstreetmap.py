# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_openstreetmap
# Purpose:      SpiderFoot plug-in to retrieve latitude/longitude coordinates
#               for physical addresses from OpenStreetMap API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-27
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import time
import urllib
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_openstreetmap(SpiderFootPlugin):
    """OpenStreetMap:Footprint,Investigate,Passive:Real World::Retrieves latitude/longitude coordinates for physical addresses from OpenStreetMap API."""

    opts = {
    }

    optdescs = {
    }

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['PHYSICAL_ADDRESS']

    # What events this module produces
    def producedEvents(self):
        return ['PHYSICAL_COORDINATES']

    # Search for address
    # https://operations.osmfoundation.org/policies/nominatim/
    def query(self, qry):
        params = {
            'q': qry.encode('raw_unicode_escape'),
            'format': 'json',
            'polygon': '0',
            'addressdetails': '0'
        }

        res = self.sf.fetchUrl("https://nominatim.openstreetmap.org/search?" + urllib.urlencode(params),
                               timeout=self.opts['_fetchtimeout'], useragent='SpiderFoot')

        if res['content'] is None:
            self.sf.info("No location info found for " + qry)
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response: " + str(e))
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        address = eventData

        # Skip post office boxes
        if address.lower().startswith('po box'):
            self.sf.debug("Skipping PO BOX address")
            return None

        # Remove address prefixes for delivery instructions
        address = re.sub(r'^(c/o|care of|attn:|attention:)\s+[0-9a-z\s\.],', r'', address, flags=re.IGNORECASE)

        # Remove address prefixes known to return no results (floor, level, suite, etc).
        address = re.sub(r'^(Level|Floor|Suite|Room)\s+[0-9a-z]+,', r'', address, flags=re.IGNORECASE)

        # Search for address
        data = self.query(eventData)

        # Usage Policy mandates no more than 1 request per second
        time.sleep(1)

        if data is None:
            self.sf.debug("Found no results for " + eventData)
            return None

        self.sf.info("Found " + str(len(data)) + " matches for " + eventData)

        for location in data:
            try:
                lat = location.get('lat')
                lon = location.get('lon')
            except BaseException as e:
                self.sf.debug("Failed to get lat/lon: " + str(e))
                continue

            if not lat or not lon:
                continue

            coords = str(lat) + "," + str(lon)
            self.sf.debug("Found coordinates: " + coords)

            evt = SpiderFootEvent("PHYSICAL_COORDINATES", coords, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_openstreetmap class
