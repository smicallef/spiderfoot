# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_adblock
# Purpose:      SpiderFoot plug-in to test if external/internally linked pages
#               would be blocked by AdBlock Plus.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     22/09/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import adblockparser
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_adblock(SpiderFootPlugin):
    """AdBlock Check:Investigate,Passive:Reputation Systems:errorprone:Check if linked pages would be blocked by AdBlock Plus."""


    # Default options
    opts = {
        "blocklist": "https://easylist-downloads.adblockplus.org/easylist.txt"
    }

    optdescs = {
        "blocklist": "AdBlockPlus block list."
    }

    results = list()
    rules = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()
        self.rules = None
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL", "LINKED_URL_EXTERNAL"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["URL_ADBLOCKED_INTERNAL", "URL_ADBLOCKED_EXTERNAL"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.errorState:
            return None

        if self.rules is None:
            raw = self.sf.fetchUrl(self.opts['blocklist'], timeout=30)
            if raw['content'] is not None:
                lines = raw['content'].split('\n')
                self.sf.debug("RULE LINES: " + str(len(lines)))
                try:
                    self.rules = adblockparser.AdblockRules(lines)
                except BaseException as e:
                    self.errorState = True
                    self.sf.error("Parsing error handling AdBlock list: " + str(e), False)
            else:
                self.errorState = True
                self.sf.error("Unable to download AdBlockPlus list: " + self.opts['blocklist'], False)

        if "_EXTERNAL" in eventName:
            pagetype = "_EXTERNAL"
        else:
            pagetype = "_INTERNAL"

        if eventData not in self.results:
            self.results.append(eventData)
        else:
            self.sf.debug("Already checked this page for AdBlock matching, skipping.")
            return None

        try:
            if self.rules and self.rules.should_block(eventData):
                evt = SpiderFootEvent("URL_ADBLOCKED" + pagetype, eventData,
                                      self.__name__, event)
                self.notifyListeners(evt)
        except BaseException as e:
            self.sf.error("Parsing error handling AdBlock list: " + str(e), False)
            self.errorState = True

        return None

# End of sfp_adblock class
