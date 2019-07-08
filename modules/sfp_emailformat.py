# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_emailformat
# Purpose:      SpiderFoot plug-in for retrieving e-mail addresses
#               belonging to your target from email-format.com.
#
# Author:      <bcoles@gmail.com>
#
# Created:     29/09/2018
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_emailformat(SpiderFootPlugin):
    """EmailFormat:Footprint,Investigate,Passive:Search Engines::Look up e-mail addresses on email-format.com."""


    results = None

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "Email-Format.com"
        self.results = dict()

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
            self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Get e-mail addresses on this domain
        if eventName == "DOMAIN_NAME":
            res = self.sf.fetchUrl("https://www.email-format.com/d/" + eventData + "/", timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

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

            if "..." in match:
                self.sf.debug("Incomplete e-mail address, skipping.")
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

# End of sfp_emailformat class
