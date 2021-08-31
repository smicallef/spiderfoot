# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_viewdns
# Purpose:     Reverse Whois lookups using ViewDNS.info API.
#
# Author:      Steve Micallef
#
# Created:     08/09/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_viewdns(SpiderFootPlugin):

    meta = {
        'name': "ViewDNS.info",
        'summary': "Reverse Whois lookups using ViewDNS.info.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://viewdns.info/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://viewdns.info/api/docs",
                "https://viewdns.info/api/"
            ],
            'apiKeyInstructions': [
                "Visit https://viewdns.info/api",
                "Select a plan",
                "Register an account",
                "Navigate to https://viewdns.info/api/dashboard/",
                "The API key is listed under 'API Key'"
            ],
            'favIcon': "https://viewdns.info/apple-touch-icon.png",
            'logo': "https://viewdns.info/images/viewdns_logo.gif",
            'description': "The ViewDNS.info API allows webmasters to integrate the tools provided by ViewDNS.info "
            "into their own sites in a simple and effective manner.",
        }
    }

    opts = {
        "api_key": "",
        "verify": True,
        "maxcohost": 100
    }

    optdescs = {
        "api_key": "ViewDNS.info API key.",
        "verify": "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        "maxcohost": "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting."
    }

    results = None
    errorState = False
    accum = list()
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.accum = list()
        self.cohostcount = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["EMAILADDR", "IP_ADDRESS", "PROVIDER_DNS"]

    def producedEvents(self):
        return ['AFFILIATE_INTERNET_NAME', 'AFFILIATE_DOMAIN_NAME', 'CO_HOSTED_SITE']

    def query(self, qry, querytype, page=1):
        if querytype == "reverseip":
            attr = "host"
            pagesize = 10000
            responsekey = "domains"
        if querytype == "reversens":
            attr = "ns"
            pagesize = 10000
            responsekey = "domains"
        if querytype == "reversewhois":
            attr = "q"
            responsekey = "matches"
            pagesize = 1000

        params = urllib.parse.urlencode({
            'apikey': self.opts['api_key'],
            attr: qry,
            'page': page,
            'output': 'json',
        })

        res = self.sf.fetchUrl(
            f"https://api.viewdns.info/{querytype}/?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )

        if res['code'] in ["400", "429", "500", "403"]:
            self.sf.error("ViewDNS.info API key seems to have been rejected or you have exceeded usage limits.")
            self.errorState = True
            return

        if res['content'] is None:
            self.sf.info(f"No ViewDNS.info data found for {qry}")
            return

        if res['content'] == 'Query limit reached for the supplied API key.':
            self.sf.error("ViewDNS.info API usage limit exceeded.")
            self.errorState = True
            return

        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.sf.error(f"Error processing JSON response from ViewDNS.info: {e}")
            return

        if not info.get("query"):
            self.sf.error("Error querying ViewDNS.info. Could be unavailable right now.")
            self.errorState = True
            return

        response = info.get("response")
        if response:
            if response.get("error"):
                self.sf.error(f"Error querying ViewDNS.info: {response.get('error')}")
                return

            if len(response.get(responsekey, list())) == pagesize:
                self.sf.debug(f"Looping at ViewDNS page {page}")
                self.accum.extend(response.get(responsekey))
                self.query(qry, querytype, page + 1)

            # We are at the last or only page
            self.accum.extend(response.get(responsekey, []))

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_viewdns but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        valkey = ""
        if eventName == "EMAILADDR":
            ident = "reversewhois"
            valkey = "domain"
        elif eventName == "IP_ADDRESS":
            ident = "reverseip"
            valkey = "name"
        elif eventName == "PROVIDER_DNS":
            if not self.getTarget().matches(eventData):
                self.sf.debug("DNS provider found but not related to target, skipping")
                return
            ident = "reversens"
            valkey = "domain"
        else:
            return

        self.accum = list()
        self.query(eventData, ident)
        rec = self.accum

        if not rec:
            return

        # Leave out registrar parking sites, and other highly used IPs
        if eventName == "IP_ADDRESS" and len(rec) > self.opts['maxcohost']:
            return

        myres = list()

        for r in rec:
            h = r.get(valkey)

            if not h:
                continue

            if h.lower() in self.results:
                continue

            if h.lower() in myres:
                continue

            if h.lower() in ["demo1.com", "demo2.com", "demo3.com", "demo4.com", "demo5.com"]:
                continue

            myres.append(h.lower())

            if eventName == "EMAILADDR":
                e = SpiderFootEvent("AFFILIATE_INTERNET_NAME", h, self.__name__, event)

                if self.sf.isDomain(h, self.opts['_internettlds']):
                    evt = SpiderFootEvent('AFFILIATE_DOMAIN_NAME', h, self.__name__, event)
                    self.notifyListeners(evt)
            else:
                if self.cohostcount >= self.opts['maxcohost']:
                    continue

                self.cohostcount += 1

                if eventName == "IP_ADDRESS" and self.opts['verify']:
                    if not self.sf.validateIP(h, eventData):
                        self.sf.debug(f"Host {h} no longer resolves to IP address: {eventData}")
                        continue
                e = SpiderFootEvent("CO_HOSTED_SITE", h, self.__name__, event)

            self.notifyListeners(e)

# End of sfp_viewdns class
