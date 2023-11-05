# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ip2locationio
# Purpose:      SpiderFoot plug-in to identify the Geo-location of IP addresses
#               identified by other modules using ip2location.io
#
# Author:      IP2Location <support@ip2location.com>
#
# Created:     25/10/2023
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ip2locationio(SpiderFootPlugin):

    meta = {
        'name': "ip2location.io",
        'summary': "Queries ip2location.io to identify geolocation of IP Addresses using ip2location.io API",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://www.ip2location.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://www.ip2location.io/ip2location-documentation"
            ],
            'apiKeyInstructions': [
                "Visit https://www.ip2location.io/",
                "Register a free account",
                "Login from https://www.ip2location.io/log-in and go to your dashboard",
                "Your API Key will be listed under API Key section.",
            ],
            'favIcon': "https://www.ip2location.io/favicon.ico",
            'logo': "https://cdn.ip2location.io/assets/img/icons/apple-touch-icon.png",
            'description': "IP2Location.io provides a fast and accurate IP Geolocation API tool "
            "to determine a user's location and use the geolocation information in different use cases. "
        }
    }

    # Default options
    opts = {
        'api_key': '',
    }

    # Option descriptions
    optdescs = {
        'api_key': "ip2location.io API Key.",
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS"
        ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [
            "GEOINFO",
            "RAW_RIR_DATA"
        ]

    def query(self, qry):
        queryString = f"https://api.ip2location.io/?key={self.opts['api_key']}&ip={qry}"

        res = self.sf.fetchUrl(queryString,
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])
        time.sleep(1.5)

        if ('error' in res):
            self.info(f"No ip2locationio data found for {qry}")
            return None
        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_ip2locationio but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData)
        if not data:
            return

        if data.get('country_name'):
            location = ', '.join(filter(None, [data.get('city_name'), data.get('region_name'), data.get('country_name'), data.get('country_code')]))
            evt = SpiderFootEvent('GEOINFO', location, self.__name__, event)
            self.notifyListeners(evt)

            if data.get('latitude') and data.get('longitude'):
                evt = SpiderFootEvent("PHYSICAL_COORDINATES", f"{data.get('latitude')}, {data.get('longitude')}", self.__name__, event)
                self.notifyListeners(evt)

            evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_ip2locationio class
