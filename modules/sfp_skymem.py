# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_skymem
# Purpose:      SpiderFoot plug-in for retrieving up to six e-mail addresses
#               belonging to your target from Skymem.
#
# Author:      Brendan Coles <bcoles@gmail.com>
#
# Created:     29/09/2018
# Copyright:   (c) Brendan Coles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_skymem(SpiderFootPlugin):
    """Skymem:Footprint,Investigate,Passive:Search Engines::Look up e-mail addresses on Skymem."""


    results = list()

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "Skymem"
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["EMAILADDR"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results.append(eventData)

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Get e-mail addresses on this domain
        if eventName == "DOMAIN_NAME":
            res = self.sf.fetchUrl("http://www.skymem.info/srch?q=" + eventData, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            return None

        pat = re.compile("([a-zA-Z\.0-9_\-]+@[a-zA-Z\.0-9\-]+\.[a-zA-Z\.0-9\-]+)")
        matches = re.findall(pat, res['content'])
        for match in matches:
            evttype = "EMAILADDR"
            self.sf.debug("Found possible email: " + match)

            # Handle false positive matches
            if len(match) < 5:
                self.sf.debug("Likely invalid address.")
                continue

            # Handle messed up encodings
            if "%" in match:
                self.sf.debug("Skipped address: " + match)
                continue

            # Skip unrelated emails
            mailDom = match.lower().split('@')[1]
            if not self.getTarget().matches(mailDom):
                self.sf.debug("Skipped address: " + match)
                continue

            self.sf.info("Found e-mail address: " + match)
            evt = SpiderFootEvent(evttype, match, self.__name__, event)
            self.notifyListeners(evt)

        return None

# End of sfp_skymem class
