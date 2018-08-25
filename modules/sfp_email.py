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

try:
    import re2 as re
except ImportError:
    import re

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_email(SpiderFootPlugin):
    """E-Mail:Footprint,Investigate,Passive:Content Analysis::Identify e-mail addresses in any obtained data."""




    # Default options
    opts = {
        # options specific to this module
    }

    # Option descriptions
    optdescs = {
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
        return ["EMAILADDR", "AFFILIATE_EMAILADDR"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # Don't re-parse e-mail addresses
        if "EMAILADDR" in eventName:
            return None

        # Ignore any web content that isn't from the target. This avoids noise from
        # pastebin and other content where unrelated e-mails are likely to be found.
        if "_CONTENT" in eventName and eventName != "TARGET_WEB_CONTENT":
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if type(eventData) not in [str, unicode]:
            try:
                if type(eventData) in [ list, dict ]:
                    eventData = str(eventData)
                else:
                    self.sf.debug("Unhandled type to find e-mails: " + str(type(eventData)))
                    return None
            except BaseException as e:
                self.sf.debug("Unable to convert list/dict to string: " + str(e))
                return None

        pat = re.compile("([\%a-zA-Z\.0-9_\-]+@[a-zA-Z\.0-9\-]+\.[a-zA-Z\.0-9\-]+)")
        matches = re.findall(pat, eventData)
        myres = list()
        for match in matches:
            evttype = "EMAILADDR"
            if len(match) < 4:
                self.sf.debug("Likely invalid address: " + match)
                continue

            # Handle messed up encodings
            if "%" in match:
                self.sf.debug("Skipped address: " + match)
                continue

            # Get the domain and strip potential ending .
            mailDom = match.lower().split('@')[1].strip('.')
            if not self.getTarget().matches(mailDom) and not self.getTarget().matches(match):
                self.sf.debug("External domain, so possible affiliate e-mail")
                # Raw RIR data returning external e-mails generates way
                # too much noise.
                if eventName == "RAW_RIR_DATA":
                    return None
                evttype = "AFFILIATE_EMAILADDR"

            self.sf.info("Found e-mail address: " + match)
            if type(match) == str:
                mail = unicode(match.strip('.'), 'utf-8', errors='replace')
            else:
                mail = match.strip('.')

            if mail in myres:
                self.sf.debug("Already found from this source.")
                continue
            else:
                myres.append(mail)

            evt = SpiderFootEvent(evttype, mail, self.__name__, event)
            if event.moduleDataSource:
                evt.moduleDataSource = event.moduleDataSource
            else:
                evt.moduleDataSource = "Unknown"
            self.notifyListeners(evt)

        return None

# End of sfp_email class
