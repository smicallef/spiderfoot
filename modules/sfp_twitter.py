#-------------------------------------------------------------------------------
# Name:         sfp_twitter
# Purpose:      Query Twitter for name and location information.
#
# Author:      Brendan Coles <bcoles@gmail.com>
#
# Created:     2018-10-17
# Copyright:   (c) Brendan Coles 2018
# Licence:     GPL
#-------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_twitter(SpiderFootPlugin):
    """Twitter:Footprint,Investigate,Passive:Social Media::Gather name and location from Twitter profiles."""

    # Default options
    opts = { 
    }

    # Option descriptions
    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "Twitter"
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ "SOCIAL_MEDIA" ]

    # What events this module produces
    def producedEvents(self):
        return [ "RAW_RIR_DATA", "GEOINFO" ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Retrieve profile
        network = eventData.split(": ")[0]
        name = eventData.split(": ")[1]

        if not network == "Twitter":
            self.sf.debug("Skipping social network profile, " + name + ", as not a Twitter profile")
            return None

        res = self.sf.fetchUrl("https://mobile.twitter.com/" + name, timeout=self.opts['_fetchtimeout'], 
                               useragent="SpiderFoot")

        if res['content'] is None:
            return None

        if not res['code'] == "200":
            self.sf.debug(name + " is not a valid Twitter profile")
            return None

        # Retrieve name
        human_name = re.findall(r'<div class="fullname">([^<]+)\s*</div>', res['content'], re.MULTILINE)

        if human_name:
            e = SpiderFootEvent("RAW_RIR_DATA", "Possible full name: " + human_name[0], self.__name__, event)
            self.notifyListeners(e)

        # Retrieve location
        location = re.findall(r'<div class="location">([^<]+)</div>', res['content'])

        if location:
            if len(location[0]) < 3 or len(location[0]) > 100:
                self.sf.debug("Skipping likely invalid location.")
            else:
                e = SpiderFootEvent("GEOINFO", location[0], self.__name__, event)
                self.notifyListeners(e)

# End of sfp_twitter class
