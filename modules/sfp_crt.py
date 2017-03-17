# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_crt
# Purpose:      SpiderFoot plug-in to identify historical certificates for a domain
#               from crt.sh, and from this identify hostnames.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     17/03/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_crt(SpiderFootPlugin):
    """Certificate Transparency:Footprint,Investigate,Passive:Networking::Gather hostnames from historical certificates in crt.sh."""

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
        return ['DOMAIN_NAME', 'INTERNET_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["INTERNET_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        res = self.sf.fetchUrl("https://crt.sh/?CN=%25." + eventData + "&output=json",
                               timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
        if res['content'] is None:
            self.sf.info("No certificate transparency info found for " + eventData)
            return None

        try:
            evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", res['content'], self.__name__, event)
            self.notifyListeners(evt)
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        return None

# End of sfp_crt class
