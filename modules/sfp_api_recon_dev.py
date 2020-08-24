# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_api_recon_dev
# Purpose:     Search api.recon.dev for subdomains.
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
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_api_recon_dev(SpiderFootPlugin):
    """api.recon.dev:Footprint,Investigate,Passive:Passive DNS::Search api.recon.dev for subdomains."""

    meta = { 
        'name': "api.recon.dev",
        'summary': "Search api.recon.dev for subdomains.",
        'flags': [ "" ],
        'useCases': [ "Footprint", "Investigate", "Passive" ],
        'categories': [ "Passive DNS" ]
    }

    opts = {
        "verify": True,
        "delay": 1
    }

    optdescs = {
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
        headers = {
            "Accept" : "application/json"
        }
        params = {
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }
        res = self.sf.fetchUrl(
            'https://api.recon.dev/search?' + urllib.parse.urlencode(params),
            headers=headers,
            timeout=30,
            useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def parseAPIResponse(self, res):
        # Future proofing - api.recon.dev does not implement rate limiting
        if res['code'] == '429':
            self.sf.error("You are being rate-limited by api.recon.dev", False)
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.sf.error("Failed to retrieve content from api.recon.dev", False)
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        # returns list of results; 'null' when no results; or dict when there's an error
        if not isinstance(data, list):
            self.sf.error("Failed to retrieve content from api.recon.dev", False)

            if isinstance(data, dict) and data.get('message'):
                self.sf.debug(f"Failed to retrieve content from api.recon.dev: {data.get('message')}")
                self.errorState = True
                return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName not in ["DOMAIN_NAME"]:
            return None

        data = self.queryDomain(eventData)

        if data is None:
            self.sf.debug("No information found for domain " + eventData)
            return None

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
                return None
            
            if domain in self.results:
                continue

            if not self.getTarget().matches(domain, includeChildren=True, includeParents=True):
                continue
        
            if self.opts['verify'] and not self.sf.resolveHost(domain):
                self.sf.debug("Host %s could not be resolved" % domain)
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", domain, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("INTERNET_NAME", domain, self.__name__, event)
                self.notifyListeners(evt)
            
        return None

# End of sfp_api_recon_dev class
