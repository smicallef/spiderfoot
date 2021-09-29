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

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_cookie(SpiderFootPlugin):

    meta = {
        'name': "Cookie Extractor",
        'summary': "Extract Cookies from HTTP headers.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

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
    def producedEvents(self):
        return ["TARGET_WEB_COOKIE"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventSource = event.actualSource

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventSource in self.results:
            return

        self.results[eventSource] = True

        fqdn = self.sf.urlFQDN(eventSource)
        if not self.getTarget().matches(fqdn):
            self.debug(f"Not collecting cookies from external sites. Ignoring HTTP headers from {fqdn}")
            return

        try:
            data = json.loads(eventData)
        except Exception:
            self.error("Received HTTP headers from another module in an unexpected format.")
            return

        cookie = data.get('cookie')
        if cookie:
            evt = SpiderFootEvent("TARGET_WEB_COOKIE", cookie, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_cookie class
