#-------------------------------------------------------------------------------
# Name:         sfp_openbugbounty
# Purpose:      Query the Open Bug Bounty database to see if our target appears.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     04/10/2015
# Copyright:   (c) Steve Micallef
# Licence:     GPL
#-------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_openbugbounty(SpiderFootPlugin):
    """Open Bug Bounty:Footprint,Investigate,Passive:Leaks, Dumps and Breaches::Check external vulnerability scanning/reporting service openbugbounty.org to see if the target is listed."""



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
        return ["INTERNET_NAME"]

    # What events this module produces
    def producedEvents(self):
        ret = ["VULNERABILITY"]

        return ret

    # Query XSSposed.org
    def queryOBB(self, qry):
        ret = list()
        base = "https://www.openbugbounty.org"
        url = "https://www.openbugbounty.org/search/?search=" + qry
        res = self.sf.fetchUrl(url, timeout=30, useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.debug("No content returned from openbugbounty.org")
            return None

        try:
            rx = re.compile(".*<div class=.cell1.><a href=.(.*).>(.*" + qry + ").*?</a></div>.*", re.IGNORECASE)
            for m in rx.findall(res['content']):
                # Report it
                if m[1] == qry or m[1].endswith("."+qry):
                    ret.append("From openbugbounty.org: <SFURL>" + base + m[0] + "</SFURL>")
        except Exception as e:
            self.sf.error("Error processing response from openbugbounty.org: " + str(e), False)
            return None
        return ret

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        data = list()

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

       # Don't look up stuff twice
        if self.results.has_key(eventData):
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        obb = self.queryOBB(eventData)
        if obb:
            data.extend(obb)

        for n in data:
            # Notify other modules of what you've found
            e = SpiderFootEvent("VULNERABILITY", n, self.__name__, event)
            self.notifyListeners(e)

# End of sfp_openbugbounty class
