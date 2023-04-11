# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ipbase
# Purpose:      SpiderFoot plug-in to identify the Geo-location of IP addresses
#               identified by other modules using ipbase.com.
#
# Author:      Dominik Kukacka <dominik@everapi.com>
#
# Created:     11/04/2023
# Copyright:   (c) Dominik Kukacka 2023
# Licence:     MIT
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ipbase(SpiderFootPlugin):

    meta = {
        'name': "ipbase",
        'summary': "Identifies the physical location of IP addresses identified using ipbase.com.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://ipbase.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://ipbase.com/docs"
            ],
            'apiKeyInstructions': [
                "Visit https://app.ipbase.com",
                "Login or register your free account",
                "The API key is shown on the dashboard or here: https://app.ipbase.com/api-keys"
            ],
            'favIcon': "https://app.ipbase.com/img/logo/ipbase.svg",
            'logo': "https://app.ipbase.com/img/logo/ipbase.svg",
            'description': "Ipbase.com is the leading API to indentify and locate your website visitors.",
        }
    }

    # Default options
    opts = {
        "api_key": ""
    }
    optdescs = {
        "api_key": "ipbase.com API key."
    }
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["GEOINFO"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_ipbase but did not set an API key!")
            self.errorState = True
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        res = self.sf.fetchUrl("https://api.ipbase.com/v2/info" + "?apikey=" + self.opts['api_key'] + "&ip=" + eventData,
                               timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
        if res['content'] is None:
            self.info("No GeoIP info found for " + eventData)

        if res['code'] == "429":
            self.error("ipbase.com API usage limits exceeded.")
            self.errorState = True
            return

        
        if res['code'] != "200":
            self.error("Error requesting geoip information.")
            self.errorState = True
            return

        try:
            hostip = json.loads(res['content'])

        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return

        geoinfo = hostip['data']['location']['country']['alpha2']
        if geoinfo:
            self.info(f"Found GeoIP for {eventData}: {geoinfo}")
            evt = SpiderFootEvent("GEOINFO", geoinfo, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_ipbase class
