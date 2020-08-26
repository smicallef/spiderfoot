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
from sflib import SpiderFootPlugin, SpiderFootEvent


class sfp_googlemaps(SpiderFootPlugin):
    """Google Maps:Footprint,Investigate,Passive:Real World:apikey:Identifies potential physical addresses and latitude/longitude coordinates."""

    meta = {
        'name': "Google Maps",
        'summary': "Identifies potential physical addresses and latitude/longitude coordinates.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://cloud.google.com/maps-platform/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://developers.google.com/maps/documentation/?_ga=2.135220017.1220421370.1587340370-900596925.1587340370"
            ],
            'apiKeyInstructions': [
                "Visit cloud.google.com/maps-platform/",
                "Register a free Google account",
                "Click on 'Get Started'",
                "Click on 'API'",
                "Select the type of API",
                "Navigate to console.cloud.google.com/apis/credentials",
                "Click on 'Credentials'",
                "The API Key will be listed under 'API Keys'"
            ],
            'favIcon': "https://www.gstatic.com/devrel-devsite/prod/v2210deb8920cd4a55bd580441aa58e7853afc04b39a9d9ac4198e1cd7fbe04ef/cloud/images/favicons/onecloud/favicon.ico",
            'logo': "https://www.gstatic.com/devrel-devsite/prod/v2210deb8920cd4a55bd580441aa58e7853afc04b39a9d9ac4198e1cd7fbe04ef/cloud/images/cloud-logo.svg",
            'description': "Explore where real-world insights and immersive location experiences can take your business.\n"
                                "Build with reliable, comprehensive data for over 200 countries and territories.\n"
                                "has been done here. If line breaks are needed for breaking up\n"
                                "Scale confidently, backed by our infrastructure.",
        }
    }

    # Default options
    opts = {
        "api_key": ""
    }
    optdescs = {
        "api_key": "Google Geocoding API Key."
    }
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['DOMAIN_NAME', 'PHYSICAL_ADDRESS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["PHYSICAL_ADDRESS", "PHYSICAL_COORDINATES", "RAW_RIR_DATA"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_googlemaps but did not set an API key!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return None
        else:
            self.results[eventData] = True

        res = self.sf.fetchUrl("https://maps.googleapis.com/maps/api/geocode/json?address=" + \
                               eventData + "&key=" + self.opts['api_key'],
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])
        if res['content'] is None:
            self.sf.info("No location info found for " + eventData)
            return None

        evt = SpiderFootEvent("RAW_RIR_DATA", res['content'],
                              self.__name__, event)
        self.notifyListeners(evt)

        try:
            data = json.loads(res['content'])['results'][0]

            if eventName in ["PHYSICAL_ADDRESS", "DOMAIN_NAME"] and \
               srcModuleName != "sfp_googlemaps":
                if 'geometry' in data:
                    lat = str(data['geometry']['location']['lat'])
                    lng = str(data['geometry']['location']['lng'])
                    evt = SpiderFootEvent("PHYSICAL_COORDINATES", lat + "," + lng, self.__name__, event)
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
