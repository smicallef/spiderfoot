#-------------------------------------------------------------------------------
# Name:         sfp_psbdmp
# Purpose:      Query psbdmp.cc for potentially hacked e-mail addresses.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     21/11/2016
# Copyright:   (c) Steve Micallef
# Licence:     GPL
#-------------------------------------------------------------------------------

import re
import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_psbdmp(SpiderFootPlugin):
    """Psbdmp.com:Footprint,Investigate,Passive:Leaks, Dumps and Breaches::Check psbdmp.cc (PasteBin Dump) for potentially hacked e-mails and domains."""


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
        ret = ["EMAILADDR", "DOMAIN_NAME", "INTERNET_NAME"]

        return ret

    # What events this module produces
    def producedEvents(self):
        ret = ["LEAKSITE_URL"]

        return ret

    def query(self, qry):
        ret = None

        if "@" in qry:
            url = "https://psbdmp.cc/api/search/email/" + qry
        else:
            url = "https://psbdmp.cc/api/search/domain/" + qry

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
            useragent="SpiderFoot")

        if res['code'] == "403":
            self.sf.info("Unable to fetch data from psbdmp.cc right now.")
            return None

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from psbdmp.cc: " + str(e), False)
            return None
        
        ids = list()
        if 'count' in ret:
            if ret['count'] > 0:
                for d in ret['data']:
                    ids.append("https://psbdmp.cc/" + d['id'])
            else:
                return None
        else:
            return None    

        return ids

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
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
            e = SpiderFootEvent("LEAKSITE_URL", n, self.__name__, event)
            self.notifyListeners(e)

            res = self.sf.fetchUrl(n, timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])

            if res['content'] is None:
                self.sf.debug("Ignoring " + n + " as no data returned")
                continue

            # Sometimes pastes search results false positives
            if re.search("[^a-zA-Z\-\_0-9]" + re.escape(eventData) +
                         "[^a-zA-Z\-\_0-9]", res['content'], re.IGNORECASE) is None:
              continue

            try:
                startIndex = res['content'].index(eventData)
            except BaseException as e:
                self.sf.debug("String not found in pastes content.")
                continue

            evt = SpiderFootEvent("LEAKSITE_CONTENT", res['content'], self.__name__, e)
            self.notifyListeners(evt)

# End of sfp_psbdmp class
