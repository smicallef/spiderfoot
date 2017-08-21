# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_base64
# Purpose:      Identifies (best-effort) Base64-encoded strings in content and URLs.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     31/01/2017
# Copyright:   (c) Steve Micallef 2017
# -------------------------------------------------------------------------------

import base64
import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_base64(SpiderFootPlugin):
    """Base64:Investigate:Content Analysis::Identify Base64-encoded strings in any content and URLs, often revealing interesting hidden information."""


    # Default options
    opts = {
        'minlength': 10
    }

    # Option descriptions
    optdescs = {
        'minlength': "The minimum length a string that looks like a base64-encoded string needs to be."
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "Target Website"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL", "TARGET_WEB_CONTENT"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["BASE64_DATA"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        pat = re.compile("([A-Za-z0-9+\/]+\=\=|[A-Za-z0-9+\/]+\=)")
        m = re.findall(pat, eventData)
        for match in m:
            minlen = int(self.opts['minlength'])
            if len(match) >= minlen:
                caps = sum(1 for c in match if c.isupper())
                # Base64-encoded strings don't look like normal strings
                if caps < (minlen/4):
                    return None
                self.sf.info("Found Base64 string: " + match)
                if type(match) == str:
                    string = unicode(match, 'utf-8', errors='replace')
                else:
                    string = match

                try:
                    string += " (" + base64.b64decode(match) + ")"
                    evt = SpiderFootEvent("BASE64_DATA", string, self.__name__, event)
                    self.notifyListeners(evt)
                except BaseException as e:
                    self.sf.debug("Unable to base64-decode a string.")

        return None

# End of sfp_base64 class
