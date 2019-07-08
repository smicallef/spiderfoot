#-------------------------------------------------------------------------------
# Name:         sfp_myspace
# Purpose:      Query MySpace for username and location information.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-07
# Copyright:   (c) bcoles 2018
# Licence:     GPL
#-------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_myspace(SpiderFootPlugin):
    """MySpace:Footprint,Investigate,Passive:Social Media::Gather username and location from MySpace.com profiles."""

    # Default options
    opts = { 
    }

    # Option descriptions
    optdescs = {
    }

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "MySpace.com"
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [ "EMAILADDR", "SOCIAL_MEDIA" ]

    # What events this module produces
    def producedEvents(self):
        return [ "SOCIAL_MEDIA", "GEOINFO" ]

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

        # Search by email address
        if eventName == "EMAILADDR":
            email = eventData
            res = self.sf.fetchUrl("https://myspace.com/search/people?q=" + email, 
                                   timeout=self.opts['_fetchtimeout'], 
                                   useragent=self.opts['_useragent'])

            if res['content'] is None:
                self.sf.error("Could not fetch MySpace content for " + email, False)
                return None

            # Extract HTML containing potential profile matches
            profiles = re.findall(r'<a href="/[a-zA-Z0-9_]+">[^<]+</a></h6>', res['content'])

            if not profiles:
                self.sf.debug("No profiles found with that e-mail.")
                return None

            # The first result is the closest match, but whether it's an exact match is unknown.
            profile = profiles[0]

            # Check for email address as name, at the risk of missed results.
            try:
                matches = re.findall('<a href=\"\/([a-zA-Z0-9_]+)\".*[\&; :\"\#\*\(\"\'\;\,\>\.\?\!]+' + email + '[\&; :\"\#\*\)\"\'\;\,\<\.\?\!]+', profile, re.IGNORECASE)
            except BaseException as e:
                self.sf.debug("Malformed e-mail address, skipping.")
                return None

            if not matches:
                self.sf.debug("No concrete match for that e-mail.")
                return None

            name = matches[0]
            e = SpiderFootEvent("SOCIAL_MEDIA", "MySpace: " + "https://myspace.com/" + name, 
                                self.__name__, event)
            self.notifyListeners(e)

        # Retrieve location from MySpace profile
        if eventName == "SOCIAL_MEDIA":
            try:
                network = eventData.split(": ")[0]
                url = eventData.split(": ")[1]
            except BaseException as e:
                self.sf.error("Unable to parse SOCIAL_MEDIA: " +
                              eventData + " (" + str(e) + ")", False)
                return None

            if network != "MySpace":
                self.sf.debug("Skipping social network profile, " + url + \
                              ", as not a MySpace profile")
                return None

            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
                                   useragent=self.opts['_useragent'])

            if res['content'] is None:
                return None

            data = re.findall(r'<div class="location_[^"]+" data-display-text="(.+?)"', res['content'])

            if not data:
                return None

            location = data[0]

            if len(location) < 5 or len(location) > 100:
               self.sf.debug("Skipping likely invalid location.")
               return None

            e = SpiderFootEvent("GEOINFO", location, self.__name__, event)
            self.notifyListeners(e)

# End of sfp_myspace class
