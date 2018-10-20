# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_opencorporates
# Purpose:      SpiderFoot plug-in for retrieving company location and previous
#               company names from OpenCorporates.
#
# Author:      Brendan Coles <bcoles@gmail.com>
#
# Created:     2018-10-21
# Copyright:   (c) Brendan Coles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import urllib
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_opencorporates(SpiderFootPlugin):
    """OpenCorporates:Passive,Footprint,Investigate:Search Engines::Look up company information from OpenCorporates."""

    # Default options
    opts = {
        'confidence': 100
    }

    # Option descriptions
    optdescs = {
        'confidence': "Confidence that the search result objects are correct (numeric value between 0 and 100)."
    }

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "OpenCorporates"
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["COMPANY_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["AFFILIATE_COMPANY_NAME", "GEOINFO"]

    # Query the REST API
    # https://api.opencorporates.com/documentation/API-Reference
    def query(self, qry):
        params = {
            'q': qry,
            'format': 'json',
            'order': 'score',
            'confidence': str(self.opts['confidence'])
        }
        res = self.sf.fetchUrl("https://api.opencorporates.com/v0.4/companies/search?" + urllib.urlencode(params),
                               timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

        return res['content']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Query the API for company information
        res = self.query(eventData + "*")

        if res is None:
            return None

        # Parse response content as JSON
        try:
            data = json.loads(res)
        except Exception as e:
            self.sf.debug("Error processing JSON response: " + str(e))
            return None

        if 'results' not in data:
            self.sf.debug("Found no results for " + eventData)
            return None

        if 'companies' not in data['results']:
            self.sf.debug("Found no results for " + eventData)
            return None

        # Check for a match
        for company in data['results']['companies']:
            if not eventData.lower() == company['company']['name'].lower():
                continue

            # Extract registered address
            location = company['company']['registered_address_in_full']

            if location is not None:
                if len(location) < 3 or len(location) > 100:
                    self.sf.debug("Skipping likely invalid location.")
                else:
                    if company['company']['registered_address'] is not None:
                        if company['company']['registered_address']['country'] is not None:
                            country = company['company']['registered_address']['country']
                            if not location.endswith(country):
                                location = location + ", " + country

                    self.sf.info("Found company address: " + location)
                    e = SpiderFootEvent("GEOINFO", location, self.__name__, event)
                    self.notifyListeners(e)

            # Extract previous company names
            previous_names = company['company']['previous_names']

            if previous_names is not None:
                for previous_name in previous_names:
                    p = previous_name['company_name']
                    self.sf.info("Found previous company name: " + p)
                    e = SpiderFootEvent("AFFILIATE_COMPANY_NAME", p, self.__name__, event)
                    self.notifyListeners(e)

# End of sfp_opencorporates class
