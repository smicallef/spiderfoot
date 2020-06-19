# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_riskiq
# Purpose:      Query RiskIQ/PassiveTotal using their API
#
# Author:      Steve Micallef
#
# Created:     16/02/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import base64
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_riskiq(SpiderFootPlugin):
    """RiskIQ:Investigate,Passive:Reputation Systems:apikey:Obtain information from RiskIQ's (formerly PassiveTotal) Passive DNS and Passive SSL databases."""


    # Default options
    opts = {
        "api_key_login": "",
        "api_key_password": "",
        "verify": True,
        "cohostsamedomain": False,
        'maxcohost': 100
    }

    # Option descriptions
    optdescs = {
        "api_key_login": "RiskIQ login.",
        "api_key_password": "RiskIQ API Key.",
        "verify": "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        "cohostsamedomain": "Treat co-hosted sites on the same target domain as co-hosting?",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS", "DOMAIN_NAME", "EMAILADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["IP_ADDRESS", "INTERNET_NAME", "AFFILIATE_INTERNET_NAME",
                "DOMAIN_NAME", "AFFILIATE_DOMAIN_NAME",
                "CO_HOSTED_SITE", "NETBLOCK_OWNER"]

    def query(self, qry, qtype, opts=dict()):
        ret = None
        post = None

        if self.errorState:
            return None

        if qtype == "PDNS":
            url = "https://api.passivetotal.org/v2/dns/search/keyword"
            post = '{"query": "' + qry + '"}'
        if qtype == "PSSL":
            url = "https://api.passivetotal.org/v2/ssl-certificate/search"
            post = '{"field": "subjectCommonName", "query": "' + qry + '"}'
        if qtype == "WHOIS":
            url = "https://api.passivetotal.org/v2/whois/search"
            post = '{"field": "email", "query": "' + qry + '"}'

        api_key_login = self.opts['api_key_login']
        if type(api_key_login) == str:
            api_key_login = api_key_login.encode('utf-8')
        api_key_password = self.opts['api_key_password']
        if type(api_key_password) == str:
            api_key_password = api_key_password.encode('utf-8')
        cred = base64.b64encode(api_key_login + ":".encode('utf-8') + api_key_password)
        headers = {
            'Authorization': "Basic " + cred.decode('utf-8'),
            'Content-Type': 'application/json'
        }

        # Be more forgiving with the timeout as some queries for subnets can be slow
        res = self.sf.fetchUrl(url, timeout=30,
                               useragent="SpiderFoot", headers=headers,
                               postData=post)

        if res['code'] in [ "400", "429", "500", "403" ]:
            self.sf.error("RiskIQ access seems to have been rejected or you have exceeded usage limits.", False)
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.info("No RiskIQ info found for " + qry)
            return None

        try:
            ret = json.loads(res['content'])
            if 'results' not in ret:
                self.sf.info("No RiskIQ info found for " + qry)
                return None
        except BaseException as e:
            self.sf.error("Invalid JSON returned by RiskIQ.", False)
            return None

        return ret['results']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        ret = None

        if self.errorState:
            return None

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        # Ignore messages from myself
        if srcModuleName == "sfp_riskiq":
            self.sf.debug("Ignoring " + eventName + ", from self.")
            return None

        if self.opts['api_key_login'] == "" or self.opts['api_key_password'] == "":
            self.sf.error("You enabled sfp_riskiq but did not set an credentials!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if eventName in [ 'DOMAIN_NAME' ]:
            ret = self.query(eventData, "PSSL")
            if not ret:
                self.sf.info("No RiskIQ passive SSL data found for " + eventData)

            if ret:
                try:
                    # Generate an event for the IP first, and then link the cert
                    # to that event.
                    for res in ret:
                        if res['subjectCommonName'] == eventData:
                            continue
                        if self.getTarget().matches(res['subjectCommonName'], includeChildren=True):
                            e = SpiderFootEvent("INTERNET_NAME", res['subjectCommonName'],
                                                self.__name__, event)
                            self.notifyListeners(e)
                            if self.sf.isDomain(res['subjectCommonName'], self.opts['_internettlds']):
                                e = SpiderFootEvent("DOMAIN_NAME", res['subjectCommonName'],
                                                    self.__name__, event)
                                self.notifyListeners(e)
                except BaseException as e:
                    self.sf.error("Invalid response returned from RiskIQ: " + str(e), False)

        if eventName == 'EMAILADDR':
            ret = self.query(eventData, "WHOIS")
            if not ret:
                self.sf.info("No RiskIQ passive DNS data found for " + eventData)
                return None

            for r in ret:
                if not eventData.endswith("@" + r['domain']):
                    if self.sf.validIP(r['domain']):
                        t = "NETBLOCK_OWNER"
                    else:
                        t = "AFFILIATE_INTERNET_NAME"
                    e = SpiderFootEvent(t, r['domain'], self.__name__, event)
                    self.notifyListeners(e)

                    if t == "AFFILIATE_INTERNET_NAME" and self.sf.isDomain(r['domain'], self.opts['_internettlds']):
                        evt = SpiderFootEvent("AFFILIATE_DOMAIN_NAME", r['domain'], self.__name__, event)
                        self.notifyListeners(evt)

            return None

        if eventName in [ 'IP_ADDRESS', 'INTERNET_NAME', 'DOMAIN_NAME' ]:
            ret = self.query(eventData, "PDNS")
            if not ret:
                self.sf.info("No RiskIQ passive DNS data found for " + eventData)
                return None

            cohosts = list()
            if eventName == "IP_ADDRESS":
                for r in ret:
                    if r['focusPoint'].endswith("."):
                        r['focusPoint'] = r['focusPoint'][:-1]

                    # Record could be pointing to our IP, or from our IP
                    if not self.getTarget().matches(r['focusPoint']) and "*" not in r['focusPoint']:
                        # We found a co-host
                        cohosts.append(r['focusPoint'])

            if eventName in [ "INTERNET_NAME", "DOMAIN_NAME" ]:
                # Record could be an A/CNAME of this entity, or something pointing to it
                for r in ret:
                    if r['focusPoint'].endswith("."):
                        r['focusPoint'] = r['focusPoint'][:-1]

                    if r['focusPoint'] != eventData and "*" not in r['focusPoint']:
                        cohosts.append(r['focusPoint'])

            for co in cohosts:
                if co == eventData:
                    continue

                if eventName == "IP_ADDRESS" and (self.opts['verify'] and not self.sf.validateIP(co, eventData)):
                    self.sf.debug("Host no longer resolves to our IP.")
                    continue

                if not self.opts['cohostsamedomain']:
                    if self.getTarget().matches(co, includeParents=True):
                        e = SpiderFootEvent("INTERNET_NAME", co, self.__name__, event)
                        self.notifyListeners(e)
                        if self.sf.isDomain(co, self.opts['_internettlds']):
                            e = SpiderFootEvent("DOMAIN_NAME", co, self.__name__, event)
                            self.notifyListeners(e)
                        continue

                if self.cohostcount < self.opts['maxcohost']:
                    e = SpiderFootEvent("CO_HOSTED_SITE", co, self.__name__, event)
                    self.notifyListeners(e)
                    self.cohostcount += 1

# End of sfp_riskiq class
