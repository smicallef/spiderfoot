# -------------------------------------------------------------------------------
# Name:         sfp_punkspider
# Purpose:      Query the QOMPLX PunkSpider API to see if our target appears.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/08/2021
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import hashlib
import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_punkspider(SpiderFootPlugin):

    meta = {
        'name': "PunkSpider",
        'summary': "Check the QOMPLX punkspider.io service to see if the target is listed as vulnerable.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://punkspider.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'logo': "https://punkspider.io/img/logo.svg",
            'description': "The idea behind Punkspider is very simple - we're doing a bunch "
            "of complicated stuff to find insecurities in massive amounts of websites, with "
            "the goal of scanning the entire Internet."
        }
    }
    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
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
        return ["INTERNET_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["VULNERABILITY_GENERAL"]

    def query(self, domain: str):
        domain_hash = hashlib.md5(domain.encode('utf-8', errors='replace').lower()).hexdigest()  # noqa: DUO130
        url = f"https://api.punkspider.org/api/partial-hash/{domain_hash}"
        res = self.sf.fetchUrl(url, timeout=30, useragent=self.opts['_useragent'])

        return self.parseApiResponse(res)

    def parseApiResponse(self, res: dict):
        if not res:
            self.error("No response from PunkSpider.")
            return None

        if res['code'] == '404':
            self.debug("No results from PunkSpider.")
            return None

        if res['code'] == '500' or res['code'] == '502' or res['code'] == '503':
            self.error("PunkSpider service is unavailable.")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error(f"Unexpected reply from PunkSpider: {res['code']}")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from PunkSpider: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {event.module}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        res = self.query(eventData)
        if not res:
            return

        for rec in res:
            if 'vulns' not in res[rec]:
                continue

            for vuln in res[rec]['vulns']:
                if res[rec]['vulns'][vuln] == 0:
                    continue
                e = SpiderFootEvent("VULNERABILITY_GENERAL", f"{vuln}: {res[rec]['vulns'][vuln]}", self.__name__, event)
                self.notifyListeners(e)

# End of sfp_punkspider class
