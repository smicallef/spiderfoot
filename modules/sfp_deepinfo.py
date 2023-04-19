# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_deepinfo
# Purpose:      Query Deepinfo using their API
#
# Author:      Ceylan Bozogullarindan
#
# Created:     16/04:/2022
# Copyright:   (c) Deepinfo 2023
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
from spiderfoot import SpiderFootEvent, SpiderFootPlugin

class sfp_deepinfo(SpiderFootPlugin):
    meta = {
        'name': "Deepinfo",
        'summary': "Obtain Passive DNS and other information from Deepinfo",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://deepinfo.com/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://docs.deepinfo.com/docs/getting-started"
            ],
            'apiKeyInstructions': [
                "Visit https://deepinfo.info/request-demo",
                "Request a demo account",
                "Navigate to https://platform.deepinfo.com/app/settings/organization/api-keys",
                "The API key is listed under 'API Keys'"
            ],
            'favIcon': "https://ik.imagekit.io/deepinfo/test/favicon/favicon-96x96.png",
            'logo': "https://ik.imagekit.io/deepinfo/test/favicon/favicon-96x96.png",
            'description': "Deepinfo provides relevant data and insights that empower "
            "cybersecurity professionals by providing access to an extensive database and reliable indicators."
            "Deepinfo has the data you need to understand what's going on on the Internet, we are dealing with "
            "terabytes of data, hundreds of data sources, billions of lines of raw data.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
    }

    # Option descriptions
    optdescs = {
        "api_key": "Deepinfo API key.",
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
        return ["DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["DOMAIN_NAME",
                "INTERNET_NAME"
                ]

    # Search Deepinfo
    def query(self, qry, page=1, accum=None):
        url = f"https://api.deepinfo.com/v1/discovery/subdomain-finder?domain={qry}&page={page}"
        request = None
        headers = {"apikey": self.opts['api_key']}
        res = self.sf.fetchUrl(url,
                               useragent="SpiderFoot", headers=headers,
                               postData=request)

        if res['code'] not in ["200"]:
            self.error("Deepinfo API key seems to have been rejected or you have exceeded usage limits for the month.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info("No Deepinfo info found for " + qry)
            return None

        try:
            info = json.loads(res['content'])
            self.info("result_count {0}, page {1}".format(info.get("result_count"), page))
            if info.get("result_count", 0) > 100:
                domains = [item.get("punycode", "") for item in info.get("results", [])]
                if len(domains) >= 100:
                    # Avoid throttling
                    time.sleep(1)
                    if accum:
                        accum.extend(domains)
                    else:
                        accum = domains
                    return self.query(qry, page + 1, accum)
                else:
                    # We are at the last page
                    accum.extend(domains)
                    return accum
            else:
                return info.get('results', [])
        except Exception as e:
            self.error("Error processing JSON response from Deepinfo: " + str(e))
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
            self.error("You enabled sfp_deepinfo but did not set an API uid/secret!")
            self.errorState = True
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName in ["DOMAIN_NAME"]:
            domain = eventData
            rec = self.query(domain)
            myres = list()
            if rec is not None:
                for h in rec:
                    if h == "":
                        continue
                    if h.lower() not in myres:
                        myres.append(h.lower())
                    else:
                        continue
                    e = SpiderFootEvent("INTERNET_NAME", h,
                                        self.__name__, event)
                    self.notifyListeners(e)
