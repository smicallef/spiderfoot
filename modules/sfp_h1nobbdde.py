#-------------------------------------------------------------------------------
# Name:         sfp_h1.nobbd.de
# Purpose:      Query the the unofficial HackerOne disclosure timeline database 
#               to see if our target appears.
#
# Author:      Dhiraj Mishra <dhiraj@notsosecure.com>
# Created:     28/10/2018
# Copyright:   (c) Dhiraj Mishra
# Licence:     GPL
#-------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_h1nobbdde(SpiderFootPlugin):
    """HackerOne (Unofficial):Footprint,Investigate,Passive:Leaks, Dumps and Breaches::Check external vulnerability scanning/reporting service h1.nobbd.de to see if the target is listed."""

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
	
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["VULNERABILITY"]

    # Query h1.nobbd.de
    def queryOBB(self, qry):
        ret = list()
        base = "http://www.h1.nobbd.de"
        url = "http://h1.nobbd.de/search.php?q=" + qry
        res = self.sf.fetchUrl(url, timeout=30, useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.debug("No content returned from h1.nobbd.de")
            return None

        try:
            rx = re.compile("<a class=\"title\" href=.(.[^\"]+).*?title=.(.[^\"\']+)", re.IGNORECASE|re.DOTALL)
            for m in rx.findall(res['content']):
                # Report it
                if qry in m[1]:
                    ret.append(m[1] + "\n<SFURL>" + m[0] + "</SFURL>")
        except Exception as e:
            self.sf.error("Error processing response from h1.nobbd.de: " + str(e), False)
            return None
        return ret

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        data = list()

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.results.has_key(eventData):
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        obb = self.queryOBB(eventData)
        if obb:
            data.extend(obb)

        for n in data:
            e = SpiderFootEvent("VULNERABILITY", n, self.__name__, event)
            self.notifyListeners(e)

# End of sfp_h1nobbdde class
