#-------------------------------------------------------------------------------
# Name:         sfp_hunter
# Purpose:      Query hunter.io using their API.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     22/02/2017
# Copyright:   (c) Steve Micallef
# Licence:     GPL
#-------------------------------------------------------------------------------

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_hunter(SpiderFootPlugin):
    """Hunter.io:Footprint,Investigate,Passive:Search Engines:apikey:Check for e-mail addresses and names on hunter.io."""


    # Default options
    opts = { 
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "api_key": "Hunter.io API key."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ "DOMAIN_NAME", "INTERNET_NAME" ]

    # What events this module produces
    def producedEvents(self):
        return [ "EMAILADDR", "RAW_RIR_DATA" ]

    def query(self, t):
        ret = None

        url = "https://api.hunter.io/v2/domain-search?domain=" + t + "&api_key=" + self.opts['api_key']

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
            useragent="SpiderFoot")

        if res['code'] == "404":
            return None

        if not res['content']:
            return None

        try:
            ret = json.loads(res['content'])['data']
        except Exception as e:
            self.sf.error("Error processing JSON response from hunter.io: " + str(e), False)
            return None

        return ret

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

       # Don't look up stuff twice
        if self.results.has_key(eventData):
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_hunter but did not set an API key!", False)
            self.errorState = True
            return None

        data = self.query(eventData)
        if data == None:
            return None

        if 'emails' not in data:
            return None

        for email in data['emails']:
            # Notify other modules of what you've found
            e = SpiderFootEvent("EMAILADDR", email['value'], self.__name__, event)
            self.notifyListeners(e)

            if 'first_name' in email and 'last_name' in email:
                if email['first_name'] != None and email['last_name'] != None:
                    n = email['first_name'] + " " + email['last_name']
                    e = SpiderFootEvent("RAW_RIR_DATA", "Possible full name: " + n, 
                                        self.__name__, event)
                    self.notifyListeners(e)


# End of sfp_hunter class
