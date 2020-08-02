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

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_cookie(SpiderFootPlugin):
    """Cookie Extractor:Footprint,Investigate,Passive:Content Analysis::Extract Cookies from HTTP headers."""

    # Default options
    opts = {}
    optdescs = {}

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
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
        eventSource = event.actualSource

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))
        if eventSource in self.results:
            return None
        else:
            self.results[eventSource] = True

        if not self.getTarget().matches(self.sf.urlFQDN(eventSource)):
            self.sf.debug("Not collecting cookies from external sites.")
            return None

        try:
            jdata = json.loads(eventData)
            if jdata == None:
                return None
        except BaseException as e:
            self.sf.error("Received HTTP headers from another module in an unexpected format.", False)
            return None

        if 'set-cookie' in jdata:
            evt = SpiderFootEvent("TARGET_WEB_COOKIE", jdata['set-cookie'],
                                  self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_cookie class
