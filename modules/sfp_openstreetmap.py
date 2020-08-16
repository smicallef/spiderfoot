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

import re
import json
import time
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_openstreetmap(SpiderFootPlugin):
    """OpenStreetMap:Footprint,Investigate,Passive:Real World::Retrieves latitude/longitude coordinates for physical addresses from OpenStreetMap API."""

    opts = {
    }

    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
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
            'q': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'format': 'json',
            'polygon': '0',
            'addressdetails': '0'
        }

        res = self.sf.fetchUrl("https://nominatim.openstreetmap.org/search?" + urllib.parse.urlencode(params),
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

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

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

        rx1 = re.compile(r'^(c/o|care of|attn:|attention:)\s+[0-9a-z\s\.]', flags=re.IGNORECASE)
        # Remove address prefixes for delivery instructions
        address = re.sub(rx1, r'', address)

        rx2 = re.compile(r'^(Level|Floor|Suite|Room)\s+[0-9a-z]+,', flags=re.IGNORECASE)
        # Remove address prefixes known to return no results (floor, level, suite, etc).
        address = re.sub(rx2, r'', address)

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
