#-------------------------------------------------------------------------------
# Name:         sfp_haveibeenpwned
# Purpose:      Query haveibeenpwned.com to see if an e-mail account has been hacked.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     19/02/2015
# Copyright:   (c) Steve Micallef
# Licence:     GPL
#-------------------------------------------------------------------------------

import json
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_haveibeenpwned(SpiderFootPlugin):
    """HaveIBeenPwned:Footprint,Investigate,Passive:Leaks, Dumps and Breaches:apikey:Check HaveIBeenPwned.com for hacked e-mail addresses identified in breaches."""


    # Default options
    opts = { 
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "api_key": "HaveIBeenPwned.com API key."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["EMAILADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["EMAILADDR_COMPROMISED"]

    def query(self, qry):
        ret = None
        if self.opts['api_key']:
            v = "3"
        else:
            v = "2"

        url = "https://haveibeenpwned.com/api/v" + v + "/breachedaccount/" + qry
        hdrs = { "Accept": "application/vnd.haveibeenpwned.v" + v + "+json" }
        retry = 0

        if self.opts['api_key']:
            hdrs['hibp-api-key'] = self.opts['api_key']
            
        while retry < 2:
            # https://haveibeenpwned.com/API/v2#RateLimiting
            time.sleep(1.5)
            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
                                   useragent="SpiderFoot", headers=hdrs)

            if res['code'] == "200":
                break

            if res['code'] == "404":
                return None

            if res['code'] == "429":
                # Back off a little further
                time.sleep(2)
            retry += 1

            if res['code'] == "401":
                self.sf.error("Failed to authenticate key with HaveIBeenPwned.com.", False)
                self.errorState = True
                return None

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from HaveIBeenPwned?: " + str(e), False)
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
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        data = self.query(eventData)
        if data == None:
            return None

        for n in data:
            if not self.opts['api_key']:
                site = n["Title"]
            else:
                site = n["Name"]
            evt = eventName + "_COMPROMISED"
            # Notify other modules of what you've found
            e = SpiderFootEvent(evt, eventData + " [" + site + "]",
                                self.__name__, event)
            self.notifyListeners(e)

# End of sfp_haveibeenpwned class
