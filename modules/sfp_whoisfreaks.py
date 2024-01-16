# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_whoisfreaks
# Purpose:      Query whoisfreaks.com using their API.
#
# Author:      Mian Fahad
#
# Created:     11/10/2023
# Copyright:   (c) Mian Fahad 2024
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_whoisfreaks(SpiderFootPlugin):
    meta = {
        'name': "WhoisFreaks",
        'summary': "Reverse Whois Lookup by owner email or name or company name",
        'flags': ["slow", "apiKey"],
        'useCases': ["Investigate", "Passive", "Footprint"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://whoisfreaks.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://whoisfreaks.com/products/whois-api.html"
            ],
            'apiKeyInstructions': [
                "Visit https://whoisfreaks.com/signup.html",
                "Register an account.",
                "The API key will be available on billing dashboard after signup",
                "500 Free credits upon signup",
                "select a plan to request beyond this limit",
                "Visit https://whoisfreaks.com/pricing/api-plans.html",

            ],
            'favIcon': "https://whoisfreaks.com/images/icons/favicon.ico",
            'logo': "https://whoisfreaks.com/images/logo.webp",
            'description': "Search domain names by owner email or name or company name"
                           " through our Reverse WHOIS lookup API"
        }
    }

    # Default options
    opts = {
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "api_key": "WhoisFreaks account registered API key.",
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "COMPANY_NAME",
            "HUMAN_NAME",
            "EMAILADDR",
            "EMAILADDR_GENERIC",
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            'AFFILIATE_DOMAIN_NAME'
        ]

    # Search WhoisFreaks
    def query(self, qry, querytype, page=1, accum=None):
        url = "https://api.whoisfreaks.com/v1.0/whois?whois=reverse&mode=mini&apiKey=" + self.opts['api_key']
        url += "&" + querytype + "=" + qry + "&page=" + str(page)

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent="SpiderFoot")

        if res['code'] in ["401", "429", "413", "412"]:
            self.error("WhoisFreaks API key seems to have been rejected or you have exceeded usage limits.")
            self.errorState = True
            return None

        if res['code'] in ["404", "400"]:
            self.error("Incorrect paramter or record not found.")
            self.errorState = True
            return None

        if res['code'] in ["500", "503", "504"]:
            self.error("request timed out or server error")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info("No WhoisFreaks info found for " + qry)
            return None

        try:
            info = json.loads(res['content'])

            if info.get("total_pages", 1) > 1:
                if info.get("current_page") < info.get("total_pages"):
                    if accum:
                        accum.extend(info.get('whois_domains_historical'))
                    else:
                        accum = info.get('whois_domains_historical')
                    return self.query(qry, querytype, page + 1, accum)

                # We are at the last page
                accum.extend(info.get('whois_domains_historical', []))
                return accum

            return info.get('whois_domains_historical', [])
        except Exception as e:
            self.error("Error processing JSON response from WhoisFreaks: " + str(e))
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error("You enabled whoisfreaks but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        query_type = None
        if eventName in "COMPANY_NAME":
            query_type = "company"
        elif eventName in "HUMAN_NAME":
            query_type = "owner"
        elif eventName in ["EMAILADDR", "EMAILADDR_GENERIC"]:
            query_type = "email"

        records = self.query(eventData, query_type)
        if records is not None:
            for record in records:
                domain_name = record.get('domain_name')
                if domain_name:
                    evt = SpiderFootEvent("AFFILIATE_INTERNET_NAME", domain_name, self.__name__, event)
                    self.notifyListeners(evt)

                    if self.sf.isDomain(domain_name, self.opts['_internettlds']):
                        evt = SpiderFootEvent('AFFILIATE_DOMAIN_NAME', domain_name, self.__name__, event)
                        self.notifyListeners(evt)

    # End of sfp_whoisfreaks class