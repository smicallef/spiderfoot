# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_whoisology
# Purpose:      Query whoisology.com using their API.
#
# Author:      Steve Micallef
#
# Created:     08/09/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_whoisology(SpiderFootPlugin):

    meta = {
        'name': "Whoisology",
        'summary': "Reverse Whois lookups using Whoisology.com.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://whoisology.com/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://whoisology.com/whois-database-download",
                "https://whoisology.com/tutorial"
            ],
            'apiKeyInstructions': [
                "Visit https://whoisology.com/",
                "Register a free account",
                "Navigate to https://whoisology.com/account",
                "Click on API Access",
                "Pay for Access and receive the API Key"
            ],
            'favIcon': "https://whoisology.com/img/w-logo.png",
            'logo': "https://whoisology.com/assets/images/il1.gif",
            'description': "Whoisology is a domain name ownership archive with literally billions of searchable and cross referenced domain name whois records.\n"
            "Our main focus is reverse whois which is used for cyber crime investigation / InfoSec, "
            "corporate intelligence, legal research, business development, and for good ol' fashioned poking around.",
        }
    }

    # Default options
    opts = {
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "api_key": "Whoisology.com API key.",
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["EMAILADDR"]

    # What events this module produces
    def producedEvents(self):
        return ['AFFILIATE_INTERNET_NAME', 'AFFILIATE_DOMAIN_NAME']

    # Search Whoisology
    def query(self, qry, querytype):
        url = "https://whoisology.com/api?auth=" + self.opts['api_key'] + "&request=flat"
        url += "&field=" + querytype + "&value=" + qry + "&level=Registrant|Admin|Tec|Billing|Other"

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent="SpiderFoot")

        if res['code'] in ["400", "429", "500", "403"]:
            self.error("Whoisology API key seems to have been rejected or you have exceeded usage limits.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info(f"No Whoisology info found for {qry}")
            return None

        try:
            info = json.loads(res['content'])
            if info.get("domains") is None:
                self.error("Error querying Whoisology: " + info.get("status_reason", "Unknown"))
                return None

            if len(info.get("domains", [])) == 0:
                self.debug(f"No data found in Whoisology for {qry}")
                return None

            return info.get('domains')
        except Exception as e:
            self.error(f"Error processing JSON response from Whoisology: {e}")
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
            self.error("You enabled sfp_whoisology but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        rec = self.query(eventData, "email")
        myres = list()
        if rec is not None:
            for r in rec:
                h = r.get('domain_name')
                if h:
                    if h.lower() not in myres:
                        myres.append(h.lower())
                    else:
                        continue

                    e = SpiderFootEvent("AFFILIATE_INTERNET_NAME", h, self.__name__, event)
                    self.notifyListeners(e)

                    if self.sf.isDomain(h, self.opts['_internettlds']):
                        evt = SpiderFootEvent('AFFILIATE_DOMAIN_NAME', h, self.__name__, event)
                        self.notifyListeners(evt)

# End of sfp_whoisology class
