# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_citadel
# Purpose:     SpiderFoot plug-in to search Leak-Lookup using their API,
#              for potential data breaches.
#
# Author:      sn <citadel.pw@protonmail.com>
#
# Created:     15/08/2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_citadel(SpiderFootPlugin):

    meta = {
        'name': "Leak-Lookup",
        'summary': "Searches Leak-Lookup.com's database of breaches.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://leak-lookup.com/",
            'model': "FREE_AUTH_UNLIMITED",
            'references': [
                "https://leak-lookup.com/api",
                "https://leak-lookup.com/databases"
            ],
            'apiKeyInstructions': [
                "Visit https://leak-lookup.com",
                "Register an account",
                "Login to your account",
                "Click on 'Account'",
                "Click on 'API'",
                "The API key is listed under 'API Key'"
            ],
            'favIcon': "https://leak-lookup.com/favicon.png",
            'logo': "https://leak-lookup.com/favicon.png",
            'description': "Leak-Lookup allows you to search across thousands of data breaches "
            "to stay on top of credentials that may have been compromised in the wild.\n"
            "The creators came together when they realized they had a vast trove of data "
            "that could be of great value to pen-testers seeking weaknesses in client passwords "
            "and those concerned about which of their credentials have been leaked into the wild.\n"
            "Always looking forward, Leak-Lookup invests all of its profits back into securing the "
            "latest data breaches and leaks / dumps as they become available, ensuring that "
            "as well as historical data, Leak-Lookup becomes a field leader in credential monitoring.",
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "timeout": 60
    }
    optdescs = {
        "api_key": "Leak-Lookup API key. Without this you're limited to the public API.",
        "timeout": "Custom timeout due to heavy traffic at times."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Leak-Lookup.com"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['EMAILADDR']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["EMAILADDR_COMPROMISED"]

    # Query email address
    # https://leak-lookup.com/api
    def queryEmail(self, email):
        apikey = self.opts['api_key']

        if not apikey:
            # Public API key
            apikey = "3edfb5603418f101926c64ca5dd0e409"

        params = {
            'query': email.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'type': 'email_address',
            'key': apikey
        }

        res = self.sf.fetchUrl("https://leak-lookup.com/api/search",
                               postData=urllib.parse.urlencode(params),
                               timeout=self.opts['timeout'],
                               useragent=self.opts['_useragent'])

        if res['code'] == "429":
            time.sleep(10)
            return self.queryEmail(email)

        if res['content'] is None:
            self.debug('No response from Leak-Lookup.com')
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

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.queryEmail(eventData)

        if data is None:
            return

        error = data.get('error')
        message = data.get('message')

        if error == 'true':
            self.error(f"Error encountered processing {eventData}: {message}")
            if "MISSING API" in message:
                self.errorState = True
                return
            return

        if not message:
            return

        for site in message:
            self.info(f"Found Leak-Lookup entry for {eventData}: {site}")
            evt = SpiderFootEvent("EMAILADDR_COMPROMISED", f"{eventData} [{site}]", self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_citadel class
