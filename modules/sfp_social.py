# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_social`
# Purpose:      Identify the usage of popular social networks
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     26/05/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

regexps = dict({
    "LinkedIn (Individual)": list(['.*linkedin.com/in/([a-zA-Z0-9_]+$)']),
    "LinkedIn (Company)": list(['.*linkedin.com/company/([a-zA-Z0-9_]+$)']),
    "Github": list(['.*github.com/([a-zA-Z0-9_]+)\/']),
    "Google+": list(['.*plus.google.com/([0-9]+$)']),
    "Facebook": list(['.*facebook.com/([a-zA-Z0-9_]+$)']),
    "MySpace": list(['https?://myspace.com/([a-zA-Z0-9_\.]+$)']),
    "YouTube": list(['.*youtube.com/([a-zA-Z0-9_]+$)']),
    "Twitter": list(['.*twitter.com/([a-zA-Z0-9_]{1,15}$)',
                     '.*twitter.com/#!/([a-zA-Z0-9_]{1,15}$)'
                     ]),
    "SlideShare": list(['.*slideshare.net/([a-zA-Z0-9_]+$)']),
    "Instagram": list(['.*instagram.com/([a-zA-Z0-9_\.]+)/?$'])
})


class sfp_social(SpiderFootPlugin):
    """Social Networks:Footprint:Social Media::Identify presence on social media networks such as LinkedIn, Twitter and others."""


    # Default options
    opts = {}

    # Option descriptions
    optdescs = {
        # For each option in opts you should have a key/value pair here
        # describing it. It will end up in the UI to explain the option
        # to the end-user.
    }

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.__dataSource__ = "Target Website"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["LINKED_URL_EXTERNAL"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SOCIAL_MEDIA", "USERNAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData not in self.results.keys():
            self.results[eventData] = True
        else:
            return None

        for regexpGrp in regexps.keys():
            for regex in regexps[regexpGrp]:
                bits = re.match(regex, eventData, re.IGNORECASE)
                if bits is not None:
                    self.sf.info("Matched " + regexpGrp + " in " + eventData)
                    evt = SpiderFootEvent("SOCIAL_MEDIA", regexpGrp + ": " +
                                          eventData, self.__name__, event)
                    self.notifyListeners(evt)

                    # Except for Google+, the link includes potential usernames
                    if regexpGrp != "Google+":
                        un = bits.group(1)
                        evt = SpiderFootEvent("USERNAME", bits.group(1), self.__name__, event)
                        self.notifyListeners(evt)

        return None

    # If you intend for this module to act on its own (e.g. not solely rely
    # on events from other modules, then you need to have a start() method
    # and within that method call self.checkForStop() to see if you've been
    # politely asked by the controller to stop your activities (user abort.)

# End of sfp_social class
