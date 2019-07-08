#-------------------------------------------------------------------------------
# Name:         sfp_slideshare
# Purpose:      Query SlideShare for name and location information.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-15
# Copyright:   (c) bcoles 2018
# Licence:     GPL
#-------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_slideshare(SpiderFootPlugin):
    """SlideShare:Footprint,Investigate,Passive:Social Media::Gather name and location from SlideShare profiles."""

    # Default options
    opts = { 
    }

    # Option descriptions
    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "SlideShare"
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ "SOCIAL_MEDIA" ]

    # What events this module produces
    def producedEvents(self):
        return [ "RAW_RIR_DATA", "GEOINFO" ]

    # Extract meta property contents from HTML
    def extractMeta(self, meta_property, html):
        return re.findall(r'<meta property="' + meta_property + '"\s+content="(.+)" />', html)

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
        try:
            network = eventData.split(": ")[0]
            url = eventData.split(": ")[1]
        except BaseException as e:
            self.sf.error("Unable to parse SOCIAL_MEDIA: " +
                          eventData + " (" + str(e) + ")", False)
            return None

        if not network == "SlideShare":
            self.sf.debug("Skipping social network profile, " + url + \
                          ", as not a SlideShare profile")
            return None

        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
                               useragent=self.opts['_useragent'])

        if res['content'] is None:
            return None

        # Check if the profile is valid and extract name
        human_name = self.extractMeta('slideshare:name', res['content'])

        if not human_name:
            self.sf.debug(url + " is not a valid SlideShare profile")
            return None

        e = SpiderFootEvent("RAW_RIR_DATA", "Possible full name: " + \
                            human_name[0], self.__name__, event)
        self.notifyListeners(e)

        # Retrieve location (country)
        location = self.extractMeta('slideshare:location', res['content'])

        if not location:
            return None

        if len(location[0]) < 3 or len(location[0]) > 100:
            self.sf.debug("Skipping likely invalid location.")
            return None

        e = SpiderFootEvent("GEOINFO", location[0], self.__name__, event)
        self.notifyListeners(e)

# End of sfp_slideshare class
