# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_recondev
# Purpose:     Search Recon.dev for subdomains.
#
# Authors:     <bcoles@gmail.com>
#
# Created:     2020-08-14
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_recondev(SpiderFootPlugin):

    meta = {
        'name': "Recon.dev",
        'summary': "Search Recon.dev for subdomains.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Passive DNS"],
        "dataSource": {
            "website": "https://recon.dev",
            'model': "FREE_AUTH_UNLIMITED",
            "references": ["https://recon.dev/api/docs"],
            "apiKeyInstructions": [
                "Visit https://recon.dev/",
                "Register an account",
                "Visit https://recon.dev/account and use the authentication token provided",
            ],
            "description": "At Recon.Dev our mission is to build an easy "
            "to use platform for hackers to easily discover a targets "
            "assets across the entire public internet.",
        }
    }

    opts = {
        "api_key": "",
        "verify": True,
        "delay": 1
    }

    optdescs = {
        "api_key": "Recon.dev API key.",
        "verify": "Verify identified domains still resolve to the associated specified IP address.",
        "delay": "Delay between requests, in seconds."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    def producedEvents(self):
        return ["RAW_RIR_DATA", "INTERNET_NAME"]

    def queryDomain(self, qry):
        """Query a domain

        Args:
            qry (str): domain

        Returns:
            str: API response as JSON
        """

        headers = {
            "Accept": "application/json"
        }
        params = urllib.parse.urlencode({
            'key': self.opts['api_key'],
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        })
        res = self.sf.fetchUrl(
            f"https://recon.dev/api/search?{params}",
            headers=headers,
            timeout=30,
            useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def parseAPIResponse(self, res):
        # Future proofing - recon.dev does not implement rate limiting
        if res['code'] == '429':
            self.error("You are being rate-limited by Recon.dev")
            self.errorState = True
            return None

        if res['code'] == '500':
            self.error("Error during request from either an inproper domain/API key or you have used up all your API credits for the month")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error("Failed to retrieve content from Recon.dev")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        # returns list of results; 'null' when no results; or dict when there's an error
        if not isinstance(data, list):
            self.error("Failed to retrieve content from Recon.dev")

            if isinstance(data, dict) and data.get('message'):
                self.debug(f"Failed to retrieve content from Recon.dev: {data.get('message')}")
                self.errorState = True
                return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        if eventName not in ["DOMAIN_NAME"]:
            return

        data = self.queryDomain(eventData)

        if data is None:
            self.debug(f"No information found for domain {eventData}")
            return

        evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
        self.notifyListeners(evt)

        domains = []

        for result in data:
            raw_domains = result.get('rawDomains')
            if raw_domains:
                for domain in raw_domains:
                    domains.append(domain)

        for domain in set(domains):
            if self.checkForStop():
                return

            if domain in self.results:
                continue

            if not self.getTarget().matches(domain, includeChildren=True, includeParents=True):
                continue

            if self.opts['verify'] and not self.sf.resolveHost(domain) and not self.sf.resolveHost6(domain):
                self.debug(f"Host {domain} could not be resolved")
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", domain, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("INTERNET_NAME", domain, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_recondev class
