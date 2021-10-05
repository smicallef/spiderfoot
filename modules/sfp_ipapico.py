# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ipapico
# Purpose:     SpiderFoot plug-in to identify the Geo-location of IP addresses
#              identified by other modules using ipapi.co
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     02/02/2021
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ipapico(SpiderFootPlugin):

    meta = {
        'name': "ipapi.co",
        'summary': "Queries ipapi.co to identify geolocation of IP Addresses using ipapi.co API",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://ipapi.co/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://ipapi.co/api/"
            ],
            'favIcon': "https://ipapi.co/static/images/favicon.b64f1de785e1.ico",
            'logo': "https://ipapi.co/static/images/favicon.34f0ec468301.png",
            'description': "Powerful & Simple REST API for IP Address Geolocation."
            "ipapi.co provides a REST API to find the location of an IP address.",
        }
    }

    # Default options
    opts = {
    }

    # Option descriptions
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
        queryString = f"https://ipapi.co/{qry}/json/"

        res = self.sf.fetchUrl(queryString,
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])
        time.sleep(1.5)

        if res['content'] is None:
            self.info(f"No ipapi.co data found for {qry}")
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

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData)

        if data is None:
            self.info("No results returned from ipapi.co")
            return

        if data.get('country'):
            location = ', '.join(filter(None, [data.get('city'), data.get('region'), data.get('region_code'), data.get('country_name'), data.get('country')]))
            evt = SpiderFootEvent('GEOINFO', location, self.__name__, event)
            self.notifyListeners(evt)

            evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(evt)


# End of sfp_ipapico class
