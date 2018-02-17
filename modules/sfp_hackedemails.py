#-------------------------------------------------------------------------------
# Name:         sfp_hackedemails
# Purpose:      Query hacked-emails.com to see if an e-mail account has been hacked.
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

class sfp_hackedemails(SpiderFootPlugin):
    """Hacked-Emails.com:Footprint,Investigate,Passive:Leaks, Dumps and Breaches:errorprone:Check Hacked-Emails.com for hacked e-mail addresses identified."""


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
        url = "https://hacked-emails.com/api?q=" + qry
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
            ret = json.loads(res['content'])
            if len(ret['data']) > 0:
                return ret['data']
            return None
        except Exception as e:
            self.sf.error("Error processing JSON response from Hacked-Emails.com: " + str(e), False)
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

        for n in data:
            site = n['details']
            evt = eventName + "_COMPROMISED"
            # Notify other modules of what you've found
            e = SpiderFootEvent(evt, eventData + " [" + site + "]",
                                self.__name__, event)
            self.notifyListeners(e)

# End of sfp_hackedemails class
