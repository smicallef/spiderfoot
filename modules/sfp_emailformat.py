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
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['INTERNET_NAME', "DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["EMAILADDR", "EMAILADDR_GENERIC"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        # Get e-mail addresses on this domain
        res = self.sf.fetchUrl("https://www.email-format.com/d/" + eventData + "/", timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            return None

        emails = self.sf.parseEmails(res['content'])
        for email in emails:
            # Skip unrelated emails
            mailDom = email.lower().split('@')[1]
            if not self.getTarget().matches(mailDom):
                self.sf.debug("Skipped address: " + email)
                continue

            # Skip masked emails
            if re.match("^[0-9a-f]{8}\.[0-9]{7}@", email):
                self.sf.debug("Skipped address: " + email)
                continue

            self.sf.info("Found e-mail address: " + email)
            if email.split("@")[0] in self.opts['_genericusers'].split(","):
                evttype = "EMAILADDR_GENERIC"
            else:
                evttype = "EMAILADDR"

            evt = SpiderFootEvent(evttype, email, self.__name__, event)
            self.notifyListeners(evt)

        return None

# End of sfp_emailformat class
