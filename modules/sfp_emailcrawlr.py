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
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_emailcrawlr(SpiderFootPlugin):

    meta = {
        'name': "EmailCrawlr",
        'summary': "Search EmailCrawlr for email addresses and phone numbers associated with a domain.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://emailcrawlr.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://emailcrawlr.com/docs"
            ],
            'apiKeyInstructions': [
                "Visit https://emailcrawlr.com",
                "Sign up for free account",
                "Navigate to https://emailcrawlr.com/dashboard",
                "The API key is listed under 'API Key'"
            ],
            'favIcon': "https://emailcrawlr.com/assets/fav-165eaa698b0dc774f0b250fadb2b41266e4c70dfbd7fb5fd4413e4bdecfd229d.png",
            'logo': "https://emailcrawlr.com/assets/logo_black-d136617b2fc5d52df6eea245a4db78477d8d99f873e08c24a9c3c7defe1c1379.png",
            'description': "By using the EmailCrawlr JSON API you can: "
            "Get key information about company websites.\n"
            "Find all email addresses associated with a domain.\n"
            "Get social accounts associated with an email.\n"
            "Verify email address deliverability.",
        }
    }

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
                "PHONE_NUMBER", "GEOINFO"]

    # Query domain
    # https://emailcrawlr.com/docs
    def queryDomain(self, qry):
        params = {
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }
        headers = {
            'Accept': "application/json",
            'x-api-key': self.opts['api_key']
        }

        res = self.sf.fetchUrl(
            f"https://api.emailcrawlr.com/v2/domain?{urllib.parse.urlencode(params)}",
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    # Parse API response
    def parseAPIResponse(self, res):
        if res['code'] == '404':
            self.debug("No results for query")
            return None

        if res['code'] == "401":
            self.error("Invalid EmailCrawlr API key.")
            self.errorState = True
            return None

        if res['code'] == '429':
            self.error("You are being rate-limited by EmailCrawlr")
            self.errorState = True
            return None

        if res['code'] == '503':
            self.error("EmailCrawlr service unavailable")
            self.errorState = True
            return None

        # Catch all other non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error("Failed to retrieve content from EmailCrawlr")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_emailcrawlr but did not set an API key!")
            self.errorState = True
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName in ["DOMAIN_NAME"]:
            data = self.queryDomain(eventData)

            if data is None:
                self.debug(f"No information found for domain {eventData}")
                return

            evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(evt)

            emails = data.get("emails")

            if not emails:
                self.info(f"No emails found for domain {eventData}")
                return

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
                        evt = SpiderFootEvent("RAW_RIR_DATA", f"Possible full name: {full_name}",
                                              self.__name__, event)
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
