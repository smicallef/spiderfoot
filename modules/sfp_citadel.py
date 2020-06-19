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
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_citadel(SpiderFootPlugin):
    """Leak-Lookup:Footprint,Investigate,Passive:Leaks, Dumps and Breaches:apikey:Searches Leak-Lookup.com's database of breaches."""

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

        if res['content'] is None:
            self.sf.debug('No response from Leak-Lookup.com')
            return None

        try:
            data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug('Error processing JSON response: ' + str(e))
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if self.errorState:
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already searched.")
            return None

        self.results[eventData] = True

        data = self.queryEmail(eventData)

        if data is None:
            return None

        error = data.get('error')
        message = data.get('message')

        if error == 'true':
            self.sf.error("Error encountered processing {}: {}".format( eventData, message ), False)
            if "MISSING API" in message:
                self.errorState = True
                return None
            return None

        if not message:
            return None

        for site in message:
            self.sf.info("Found Leak-Lookup entry for {}: {}".format( eventData, site ) )
            evt = SpiderFootEvent( "EMAILADDR_COMPROMISED", "{} [{}]".format( eventData, site ), self.__name__, event )
            self.notifyListeners(evt)

# End of sfp_citadel class
