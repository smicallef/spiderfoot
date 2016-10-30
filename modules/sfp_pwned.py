#-------------------------------------------------------------------------------
# Name:         sfp_pwned
# Purpose:      Query haveibeenpwned.com to see if an account has been hacked.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     19/02/2015
# Copyright:   (c) Steve Micallef
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import json
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_pwned(SpiderFootPlugin):
    """Pwned Password:Footprint,Investigate,Passive:Search Engines:errorprone:Check Have I Been Pwned? for hacked accounts identified."""

    # Default options
    opts = { 
        "lookupusernames": True
    }

    # Option descriptions
    optdescs = {
        "lookupusernames": "Also look up usernames, not just e-mail addresses. More prone to false positives for common names."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        ret = ["EMAILADDR"]

        if self.opts['lookupusernames']:
            ret.extend(["ACCOUNT_EXTERNAL_USER_SHARED", "ACCOUNT_EXTERNAL_OWNED"])

        return ret

    # What events this module produces
    def producedEvents(self):
        ret = ["EMAILADDR_COMPROMISED"]

        if self.opts['lookupusernames']:
            ret.extend(["ACCOUNT_EXTERNAL_USER_SHARED_COMPROMISED", 
                "ACCOUNT_EXTERNAL_OWNED_COMPROMISED"])

        return ret

    def query(self, qry):
        ret = None

        url = "https://haveibeenpwned.com/api/v2/breachedaccount/" + qry
        hdrs = { "Accept": "application/vnd.haveibeenpwned.v2+json" }

        # https://haveibeenpwned.com/API/v2#RateLimiting
        time.sleep(1.5)
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
            useragent="SpiderFoot", headers=hdrs)

        if res['code'] in [ 404, "404" ]:
            return None

        if res['code'] in [ 429, "429" ]:
            # Back off a little further
            time.sleep(2)

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
        if "ACCOUNT" in eventName:
            eventData = event.data.split(" ")[0]
        else:
            eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

       # Don't look up stuff twice
        if self.results.has_key(eventData):
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        data = self.query(eventData)
        if data == None:
            return None

        for n in data:
            site = n["Title"]
            evt = eventName + "_COMPROMISED"
            # Notify other modules of what you've found
            e = SpiderFootEvent(evt, eventData + " [" + site + "]",
                self.__name__, event)
            self.notifyListeners(e)

# End of sfp_pwned class
