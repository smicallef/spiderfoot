# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_opencorporates
# Purpose:      SpiderFoot plug-in for retrieving company information from
#               OpenCorporates.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-21
# Copyright:   (c) bcoles 2018
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
        'confidence': 100,
        'api_key': ''
    }

    # Option descriptions
    optdescs = {
        'confidence': "Confidence that the search result objects are correct (numeric value between 0 and 100).",
        'api_key': 'OpenCorporates.com API key.'
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
        return [ "COMPANY_NAME" ]

    # What events this module produces
    def producedEvents(self):
        return [ "COMPANY_NAME", "PHYSICAL_ADDRESS", "RAW_RIR_DATA" ]

    # Search for company name
    # https://api.opencorporates.com/documentation/API-Reference
    def searchCompany(self, qry):
        if type(qry) != unicode:
            qry = qry.encode("utf-8", errors="replace")

        apiparam = ""
        if not self.opts['api_key'] == "":
            apiparam = "&api_token=" + self.opts['api_key']

        # High timeouts as they can sometimes take a while
        res = self.sf.fetchUrl("https://api.opencorporates.com/v0.4/companies/search?q=" + \
                               qry + "&format=json&order=score&confidence=" + \
                               str(self.opts['confidence']) + apiparam,
                               timeout=60, useragent=self.opts['_useragent'])

        if res['code'] == "401":
            self.sf.error("Invalid OpenCorporates API key.", False)
            return None

        if res['code'] == "403":
            self.sf.error("You are being rate-limited by OpenCorporates.", False)
            return None

        # Parse response content as JSON
        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response: " + str(e))
            return None

        if 'results' not in data:
            return None

        return data['results']

    # Retrieve company details
    # https://api.opencorporates.com/documentation/API-Reference
    def retrieveCompanyDetails(self, jurisdiction_code, company_number):
        url = "https://api.opencorporates.com/companies/" + jurisdiction_code + "/" + str(company_number)

        if not self.opts['api_key'] == "":
            url += '?' + self.opts['api_key']

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

        if res['code'] == "401":
            self.sf.error("Invalid OpenCorporates API key.", False)
            return None

        if res['code'] == "403":
            self.sf.error("You are being rate-limited by OpenCorporates.", False)
            return None

        # Parse response content as JSON
        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response: " + str(e))
            return None

        if 'results' not in data:
            return None

        return data['results']


    # Extract company address, previous names, and officer names
    def extractCompanyDetails(self, company, sevt):

        # Extract registered address
        location = company.get('registered_address_in_full')

        if location:
            if len(location) < 3 or len(location) > 100:
                self.sf.debug("Skipping likely invalid location.")
            else:
                if company.get('registered_address'):
                    country = company.get('registered_address').get('country')
                    if country:
                        if not location.endswith(country):
                            location += ", " + country

                location = location.replace("\n", ',')
                self.sf.info("Found company address: " + location)
                e = SpiderFootEvent("PHYSICAL_ADDRESS", location, self.__name__, sevt)
                self.notifyListeners(e)

        # Extract previous company names
        previous_names = company.get('previous_names')

        if previous_names:
            for previous_name in previous_names:
                p = previous_name.get('company_name')
                if p:
                    self.sf.info("Found previous company name: " + p)
                    e = SpiderFootEvent("COMPANY_NAME", p, self.__name__, sevt)
                    self.notifyListeners(e)

        # Extract officer names
        officers = company.get('officers')

        if officers:
            for officer in officers:
                n = officer.get('name')
                if n:
                    self.sf.info("Found company officer: " + n)
                    e = SpiderFootEvent("RAW_RIR_DATA", "Possible full name: " + n, self.__name__, sevt)
                    self.notifyListeners(e)

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

        # Search for the company
        res = self.searchCompany(eventData + "*")

        if res is None:
            self.sf.debug("Found no results for " + eventData)
            return None

        companies = res.get('companies')

        if not companies:
            self.sf.debug("Found no results for " + eventData)
            return None

        for c in companies:
            company = c.get('company')

            if not company:
                continue

            # Check for match
            if not eventData.lower() == company.get('name').lower():
                continue

            # Extract company details from search results
            self.extractCompanyDetails(company, event)

            # Retrieve further details
            jurisdiction_code = company.get('jurisdiction_code')
            company_number = company.get('company_number')

            if not company_number or not jurisdiction_code:
                continue

            res = self.retrieveCompanyDetails(jurisdiction_code, company_number)

            if not res:
                continue

            c = res.get('company')

            if not c:
                continue

            self.extractCompanyDetails(c, event)

# End of sfp_opencorporates class
