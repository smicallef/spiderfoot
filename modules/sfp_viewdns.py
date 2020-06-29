# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_viewdns
# Purpose:      Query viewdns.info using their API.
#
# Author:      Steve Micallef
#
# Created:     08/09/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_viewdns(SpiderFootPlugin):
    """ViewDNS.info:Investigate,Passive:Search Engines:apikey:Reverse Whois lookups using ViewDNS.info."""

    # Default options
    opts = {
        "api_key": "",
        "verify": True,
        "maxcohost": 100
    }

    # Option descriptions
    optdescs = {
        "api_key": "ViewDNS.info API key.",
        "verify": "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        "maxcohost": "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False
    accum = list()
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.accum = list()
        self.cohostcount = 0

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["EMAILADDR", "IP_ADDRESS", "PROVIDER_DNS"]

    # What events this module produces
    def producedEvents(self):
        return ['AFFILIATE_INTERNET_NAME', 'AFFILIATE_DOMAIN_NAME', 'CO_HOSTED_SITE']

    # Search ViewDNS.info
    def query(self, qry, querytype, page=1):
        info = None

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

        url = "https://api.viewdns.info/" + querytype + "/?apikey=" + self.opts['api_key']
        url += "&" + attr + "=" + qry + "&page=" + str(page) + "&output=json"

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                               useragent="SpiderFoot")

        if res['code'] in [ "400", "429", "500", "403" ]:
            self.sf.error("ViewDNS.info API key seems to have been rejected or you have exceeded usage limits.", False)
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.info("No ViewDNS.info data found for " + qry)
            return None

        try:
            info = json.loads(res['content'])
            if not info.get("query"):
                self.sf.error("Error querying ViewDNS.info. Could be unavailable right now.", False)
                self.errorState = True
                return None
            if info.get("response"):
                r = info.get("response")
                if r.get("error"):
                    self.sf.error("Error querying ViewDNS.info: " + r.get("error", "Unknown"), False)
                    return None

                if len(r.get(responsekey, list())) == pagesize:
                    self.sf.debug("Looping at ViewDNS page " + str(page))
                    self.accum.extend(r.get(responsekey))
                    self.query(qry, querytype, page+1)
                # We are at the last or only page
                self.accum.extend(r.get(responsekey, []))
        except Exception as e:
            self.sf.error("Error processing JSON response from ViewDNS.info: " + str(e), False)
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_viewdns but did not set an API key!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        valkey = ""
        if eventName == "EMAILADDR":
            ident = "reversewhois"
            valkey = "domain"
        if eventName == "IP_ADDRESS":
            ident = "reverseip"
            valkey = "name"
        if eventName == "PROVIDER_DNS":
            if self.getTarget().matches(eventData):
                ident = "reversens"
                valkey = "domain"
            else:
                self.sf.debug("DNS provider found but not related to target, skipping")
                return None

        self.accum = list()
        self.query(eventData, ident)
        rec = self.accum

        # Leave out registrar parking sites, and other highly used IPs
        if eventName == "IP_ADDRESS" and len(rec) > self.opts['maxcohost']:
            return None

        myres = list()
        if rec is not None:
            for r in rec:
                h = r.get(valkey)
                if h:
                    if h.lower() in self.results:
                        continue
                    if h.lower() not in myres:
                        myres.append(h.lower())
                    else:
                        continue
                    if h.lower() in [ "demo1.com", "demo2.com", "demo3.com", "demo4.com", "demo5.com" ]:
                        continue
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
                                self.sf.debug("Host no longer resolves to our IP.")
                                continue
                        e = SpiderFootEvent("CO_HOSTED_SITE", h, self.__name__, event)
                    self.notifyListeners(e)

# End of sfp_viewdns class
