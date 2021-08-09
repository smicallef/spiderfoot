# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_abstractapi
# Purpose:     SpiderFoot plug-in to identify the Geolocation of IP addresses
#              from abstractapi.com Geolocation API
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     29/07/2021
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_abstractapi(SpiderFootPlugin):

    meta = {
        'name': "abstractapi",
        'summary': "Queries abstractapi.com to identify geolocation of IP Addresses using their Geolocation API",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://abstractapi.com",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://app.abstractapi.com/api/ip-geolocation/documentation"
            ],
            'apiKeyInstructions': [
                "Visit https://app.abstractapi.com/users/signup",
                "Register a free account",
                "Browse to https://app.abstractapi.com/api/ip-geolocation/tester",
                "Click on 'Try it out'",
                "Your API Key will be listed under 'This is your private API key, specific to this API.'",
            ],
            'favIcon': "https://global-uploads.webflow.com/5ebbd0a566a3996636e55959/5ec2ba27ede983917dbff22f_favicon.png",
            'logo': "https://global-uploads.webflow.com/5ebbd0a566a3996636e55959/5ec2b974e578f93e553425eb_logo-dark.svg",
            'description': "The IP Geolocation allows you to look up the location, timezone, country details, and more of an IPv4 or IPv6 address.",
        }
    }

    # Default options
    opts = {
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "api_key": "AbstractAPI Geolocation API Key"
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
            "PHYISCAL_COORDINATES",
            "RAW_RIR_DATA"
        ]

    def query(self, qry):
        queryString = f"https://ipgeolocation.abstractapi.com/v1/?api_key={self.opts['api_key']}&ip_address={qry}"

        res = self.sf.fetchUrl(queryString,
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])
        time.sleep(1.2)

        return self.parseAPIResponse(res)

    def parseAPIResponse(self, res):
        if res['code'] == '204':
            self.sf.debug("No geolocation information for target")
            return None

        if res['code'] == "400":
            self.sf.error("Bad Request")
            self.errorState = True
            return None

        if res['code'] == "401":
            self.sf.error("Unauthorized. Invalid abstractapi API key")
            self.errorState = True
            return None

        if res['code'] == '422':
            self.sf.error("Usage quota reached. Insufficient API Credit")
            self.errorState = True
            return None

        if res['code'] == '429':
            self.sf.error("Too many requests")
            return None

        if res['code'] == '500' or res['code'] == '503':
            self.sf.error("abstractapi service is unavailable")
            self.errorState = True
            return None

        if res['code'] != '200':
            self.sf.error("Failed to retrieve data from abstractapi")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug(f"Error processing JSON response: {e}")
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_abstractapi but did not set an API key!")
            self.errorState = True
            return None

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return None

        self.results[eventData] = True

        data = self.query(eventData)

        if data is None:
            self.sf.info("No results returned from abstractapi")
            return None

        if data.get('country'):
            location = ', '.join(filter(None, [data.get('city'), data.get('region'), data.get('region_iso_code'), data.get('country'), data.get('country_code'), data.get('continent'), data.get('continent_code')]))
            evt = SpiderFootEvent('GEOINFO', location, self.__name__, event)
            self.notifyListeners(evt)

            if data.get('latitude') and data.get('longitude'):
                evt = SpiderFootEvent("PHYSICAL_COORDINATES", f"{data.get('latitude')}, {data.get('longitude')}", self.__name__, event)
                self.notifyListeners(evt)

            evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(evt)


# End of sfp_abstractapi class
