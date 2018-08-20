#-------------------------------------------------------------------------------
# Name:         sfp_gotcha
# Purpose:      Query gotcha.pw to see if an e-mail account has been hacked.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     17/02/2018
# Copyright:   (c) Steve Micallef
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import json
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_gotcha(SpiderFootPlugin):
    """Gotcha.pw:Footprint,Investigate,Passive:Leaks, Dumps and Breaches::Check Gotcha.pw for hacked e-mail addresses identified."""


    # Default options
    opts = { 
    }

    # Option descriptions
    optdescs = {
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
        return ["EMAILADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["EMAILADDR_COMPROMISED"]

    def query(self, qry):
        ret = None
        url = "https://gotcha.pw/search/" + qry
        retry = 0

        while retry < 2:
            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
                                   useragent="SpiderFoot")
            if res['code'] == "200":
                break
            if res['code'] == "404":
                return None
            if res['code'] == "429":
                # Back off a little further
                time.sleep(2)
            retry += 1

        try:
            if "big-font text-danger font-weight-bold text-center\">Found" in res['content']:
                return True
        except Exception as e:
            self.sf.error("Error processing response from gotcha.pw: " + str(e), False)
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

       # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        data = self.query(eventData)
        if not data:
            return None
        else:
            # Notify other modules of what you've found
            e = SpiderFootEvent("EMAILADDR_COMPROMISED", "Unknown breach",
                                self.__name__, event)
            self.notifyListeners(e)

# End of sfp_gotcha class
