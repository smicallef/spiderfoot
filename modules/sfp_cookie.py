# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_cookie
# Purpose:      SpiderFoot plug-in for extracting cookies from HTTP headers.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_cookie(SpiderFootPlugin):
    """Cookies:Footprint,Investigate:Crawling and Scanning::Extract Cookies from HTTP headers."""


    # Default options
    opts = {}

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
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
        return ["TARGET_WEB_COOKIE"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event.sourceEvent
        eventSource = event.sourceEvent.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)
        if eventSource in self.results:
            return None
        else:
            self.results[eventSource] = True

        if not self.getTarget().matches(self.sf.urlFQDN(eventSource)):
            self.sf.debug("Not collecting cookies from external sites.")
            return None

        if 'set-cookie' in eventData:
            evt = SpiderFootEvent("TARGET_WEB_COOKIE", eventData['set-cookie'],
                                  self.__name__, parentEvent)
            self.notifyListeners(evt)

# End of sfp_cookie class
