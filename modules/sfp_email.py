# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_email
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) and identifying e-mail addresses
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_email(SpiderFootPlugin):
    """E-Mail:Footprint,Investigate:Identify e-mail addresses in any obtained data."""

    # Default options
    opts = {
        # options specific to this module
        'includeexternal': False  # Include e-mail addrs on external domains
    }

    # Option descriptions
    optdescs = {
        'includeexternal': "Report e-mail addresses not on the target base domain-name?"
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["*"]

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
        parentEvent = event.sourceEvent

        if eventName == "EMAILADDR":
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if type(eventData) not in [str, unicode]:
            self.sf.debug("Unhandled type to find e-mails: " + str(type(eventData)))
            return None

        pat = re.compile("([\%a-zA-Z\.0-9_\-]+@[a-zA-Z\.0-9\-]+\.[a-zA-Z\.0-9\-]+)")
        matches = re.findall(pat, eventData)
        for match in matches:
            if len(match) < 4:
                self.sf.debug("Likely invalid address: " + match)
                continue

            # Handle messed up encodings
            if "%" in match:
                self.sf.debug("Skipped address: " + match)
                continue

            mailDom = match.lower().split('@')[1]
            if not self.opts['includeexternal'] and not \
                    self.getTarget().matches(mailDom):
                self.sf.debug("Ignoring e-mail address on an external domain: " + match)
                continue

            self.sf.info("Found e-mail address: " + match)
            if type(match) == str:
                mail = unicode(match, 'utf-8', errors='replace')
            else:
                mail = match
            evt = SpiderFootEvent("EMAILADDR", mail, self.__name__, parentEvent)
            self.notifyListeners(evt)

        return None

# End of sfp_email class
