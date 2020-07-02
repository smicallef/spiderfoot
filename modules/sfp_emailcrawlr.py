# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_emailcrawlr
# Purpose:     Search EmailCrawlr for email addresses and phone numbers
#              associated with a domain.
#
# Authors:     <bcoles@gmail.com>
#
# Created:     2020-06-19
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_emailcrawlr(SpiderFootPlugin):
    """EmailCrawlr:Footprint,Investigate,Passive:Search Engines:apikey:Search EmailCrawlr for email addresses and phone numbers associated with a domain."""

    # Default options
    opts = {
        "api_key": "",
        "delay": 1,
    }

    # Option descriptions
    optdescs = {
        "api_key": "EmailCrawlr API key.",
        "delay": "Delay between requests, in seconds.",
    }

    results = None
    errorState = False

    # Initialize module and module options
    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["RAW_RIR_DATA", "EMAILADDR", "EMAILADDR_GENERIC",
                "PHONE_NUMBER", "GEOINFO", "HUMAN_NAME"]

    # Query domain
    # https://emailcrawlr.com/docs
    def queryDomain(self, qry):
        params = {
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }
        headers = {
            'Accept' : "application/json",
            'x-api-key' : self.opts['api_key']
        }
        
        res = self.sf.fetchUrl(
          "https://api.emailcrawlr.com/v2/domain?%s" % urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    # Parse API response
    def parseAPIResponse(self, res):
        if res['code'] == '404':
            self.sf.debug("No results for query")
            return None

        if res['code'] == "401":
            self.sf.error("Invalid EmailCrawlr API key.", False)
            self.errorState = True
            return None

        if res['code'] == '429':
            self.sf.error("You are being rate-limited by EmailCrawlr", False)
            self.errorState = True
            return None

        if res['code'] == '503':
            self.sf.error("EmailCrawlr service unavailable", False)
            self.errorState = True
            return None

        # Catch all other non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.sf.error("Failed to retrieve content from EmailCrawlr", False)
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if eventData in self.results:
            return None

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_emailcrawlr but did not set an API key!", False)
            self.errorState = True
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if eventName in ["DOMAIN_NAME"]:
            data = self.queryDomain(eventData)

            if data is None:
                self.sf.debug("No information found for domain %s" % eventData)
                return None

            evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(evt)

            emails = data.get("emails")

            if not emails:
                self.sf.info("No emails found for domain %s" % eventData)
                return None

            for res in emails:
                email = res.get('email')
                if email:
                    mail_domain = email.lower().split('@')[1]
                    if self.getTarget().matches(mail_domain, includeChildren=True):
                        if email.split("@")[0] in self.opts['_genericusers'].split(","):
                            evttype = "EMAILADDR_GENERIC"
                        else:
                            evttype = "EMAILADDR"

                        evt = SpiderFootEvent(evttype, email, self.__name__, event)
                        self.notifyListeners(evt)

                name = res.get('name')
                if name:
                    full_name = name.get('name')
                    if full_name and len(full_name) > 3:
                        evt = SpiderFootEvent("HUMAN_NAME", full_name, self.__name__, event)
                        self.notifyListeners(evt)

                phone_numbers = res.get('numbers')
                if phone_numbers:
                    for number in phone_numbers:
                        if number:
                            evt = SpiderFootEvent("PHONE_NUMBER", number, self.__name__, event)
                            self.notifyListeners(evt)

                location = res.get('location')
                if location:
                    loc = ', '.join([_f for _f in [location.get('city'), location.get('country')] if _f])
                    if loc:
                        evt = SpiderFootEvent("GEOINFO", loc, self.__name__, event)
                        self.notifyListeners(evt)

# End of sfp_emailcrawlr class
