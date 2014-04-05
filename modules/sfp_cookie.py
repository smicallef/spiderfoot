#-------------------------------------------------------------------------------
# Name:         sfp_cookie
# Purpose:      SpiderFoot plug-in for extracting cookies from HTTP headers.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_cookie(SpiderFootPlugin):
    """Cookies:Extract Cookies from HTTP headers."""

    # Default options
    opts = { }

    # Target
    baseDomain = None # calculated from the URL in setup
    results = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["WEBSERVER_HTTPHEADERS"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "TARGET_WEB_COOKIE" ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event.sourceEvent
        eventSource = event.sourceEvent.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)
        if self.results.has_key(eventSource):
            return None
        else:
            self.results[eventSource] = True

        if not sf.urlBaseUrl(eventSource).endswith(self.baseDomain):
            sf.debug("Not collecting cookies from external sites.")
            return None

        if eventData.has_key('set-cookie'):
            evt = SpiderFootEvent("TARGET_WEB_COOKIE", eventData['set-cookie'], 
                self.__name__, parentEvent)
            self.notifyListeners(evt)

            sf.info("Found cookie: " + eventData['set-cookie'] + " (" + eventSource + ")")

# End of sfp_cookie class
