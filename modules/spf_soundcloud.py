#-------------------------------------------------------------------------------
# Name:         sfp_soundcloud
# Purpose:      Query to soundcloud database 
#               to see if our target appears.
#
# Author:      Dhiraj Mishra (@mishradhiraj_)
# Created:     03/01/2019
# Copyright:   (c) Dhiraj Mishra
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import time
import datetime
import re
import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_soundcloud(SpiderFootPlugin):
    """SoundCloud:Footprint,Investigate,Passive:Leaks, Dumps and Breaches::Check gather data from soundcloud to see if the target is listed."""

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
        return ["RAW_RIR_DATA"]

    # Query SoundCloud
    def queryOBB(self, qry):
        ret = list()
        base = "https://soundcloud.com"
        url = "https://soundcloud.com/search?q=" + qry
        res = self.sf.fetchUrl(url, timeout=30, useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.debug("No content returned from soundcloud")
            return None

        try:
            rx = re.compile("<a class=\"title\" href=.(.[^\"]+).*?title=.(.[^\"\']+)", re.IGNORECASE|re.DOTALL)
            for m in rx.findall(res['content']):
                # Report it
                if qry in m[1]:
                    ret.append(m[1] + "\n<SFURL>" + m[0] + "</SFURL>")
        except Exception as e:
            self.sf.error("Error processing response from soundcloud: " + str(e), False)
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
            e = SpiderFootEvent("RAW_RIR_DATA", n, self.__name__, event)
            self.notifyListeners(e)

# End of sfp_soundcloud class
