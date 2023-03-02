# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_bevigil
# Purpose:      Search BeVigil OSINT API for subdomains.
#
# Author:      alt-glitch <https://github.com/alt-glitch>
#
# Created:     2022-08-27
# Copyright:   (c) alt-glitch 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_bevigil(SpiderFootPlugin):
    meta = {
        'name': "BeVigil API",
        'summary': "Get Subdomains belonging to one target domain using OSINT Data made available by BeVigil",
        'flags': ["apikey"],
        'useCases': ["Passive", "Footprint"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://bevigil.com/osint-api",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://bevigil.com/osint/api-documentation"
            ],
            'apiKeyInstructions': [
                "Visit https://bevigil.com/osint-api",
                "Click on 'Sign up for API Key'",
                "Enter your email to get the OTP",
                "Enter the OTP and Sign Up",
                "Click on 'Get Started' to activate your account and you will have your API key"
            ],
            'favIcon': "https://bevigil.com/favicon.ico",
            'description':"A powerful tool that provides access to millions of asset footprint "
            "data points including domain intel, cloud services, API information, and third party "
            "assets extracted from millions of mobile apps being continuously uploaded "
            "and scanned by users on bevigil.com",
        }
    }

    opts = {
        'verify': True,
        'api_key': '',
        'delay': 1
    }

    optdescs = {
        "verify": "DNS Resolve each identified subdomain.",
        "api_key": "BeVigil API Key.",
        "delay": "Delay between requests, in seconds."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        # self.__dataSource__ = "BeVigil OSINT API"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]


    def watchedEvents(self):
        return ["DOMAIN_NAME",]

    def producedEvents(self):
        return ["RAW_RIR_DATA", "INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]

    def query(self, domain):
        url = f"http://osint.bevigil.com/api/{domain}/subdomains/"
        headers = {
            "X-Access-Token": self.opts['api_key']
        }
    
        res = self.sf.fetchUrl(
            url,
            headers=headers,
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
        )
        
        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)
    
    def parseApiResponse(self, res: dict):
        if res['code'] == "400":
            self.error("Bad request sent")
            self.errorState = True
        elif res['code'] == "401":
            self.error("Access Token is Invalid. Please check the API key")
            self.errorState = True
        elif res['code'] == "402":
            self.error("You have no credits left for the month. Please purchase new credits")
            self.errorState = True
        elif res['code'] == "422":
            self.error("Rate limit exceeded")
            self.errorState = True
        elif res['code'] == "200":    
            try:
                subs: dict = json.loads(res['content'])
            except Exception as e:
                self.error(f"Error processing JSON response from BeVigil: {e}")

            # if res['content'] == [] or subs['subdomains'] == []:
            if subs['subdomains'] == []:
                self.info(f'BeVigil found no subdomains')
                return None
            else:
                return subs['subdomains']


    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return
        
        self.results[eventData] = True
        
        self.debug(f"Received event, {eventName}, from {srcModuleName}")
        
        if eventName != "DOMAIN_NAME":
            return

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_bevigil but did not set an API key!")
            self.errorState = True
            return
        
        subdomains = self.query(eventData)

        if not subdomains:
            self.debug(f"No information found for domain {eventData}")
            return

        evt = SpiderFootEvent('RAW_RIR_DATA', str(subdomains), self.__name__, event)
        self.notifyListeners(evt)

        for subdomain in set(subdomains):
            if subdomain in self.results:
                continue
            
            if not self.getTarget().matches(subdomain, includeChildren=True, includeParents=True):
                continue

            if self.opts['verify'] and not self.sf.resolveHost(subdomain) and not self.sf.resolveHost6(subdomain):
                self.debug(f"Host {subdomain} could not be resolved")
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", subdomain, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("INTERNET_NAME", subdomain, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_bevigil class