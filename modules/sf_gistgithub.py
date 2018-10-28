#-------------------------------------------------------------------------------
# Name:         sfp_gist.github.com
# Purpose:      Identifies public shared code, notes, and snippets in gist github associated with 
#               your target.
#
# Author:      Dhiraj Mishra <dhiraj@notsosecure.com>
# Created:     28/10/2018
# Copyright:   (c) Dhiraj Mishra
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import time
import datetime
import re
import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_gistgithub(SpiderFootPlugin):
     """Gist Github:Footprint,Investigate,Passive:Leaks, Dumps and Breaches::Check external vulnerability scanning/reporting service from gist.github.com to see if the target is listed."""

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
        ret = ["VULNERABILITY"]

        return ret

    # Query gist.github.com
    def queryOBB(self, qry):
        ret = list()
        base = "https://gist.github.com/"
        url = "https://gist.github.com/search?q=" + qry
        res = self.sf.fetchUrl(url, timeout=30, useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.debug("No content returned from gist.github.com")
            return None

        try:
            rx = re.compile(".*<div class=.cell1.><a href=.(.*).>(.*" + qry + ").*?</a></div>.*", re.IGNORECASE)
            for m in rx.findall(res['content']):
                # Report it
                if m[1] == qry or m[1].endswith("."+qry):
                    ret.append("From gist.github.com: <SFURL>" + base + m[0] + "</SFURL>")
        except Exception as e:
            self.sf.error("Error processing response from gist.github.com: " + str(e), False)
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

# End of sfp_gistgithub class
