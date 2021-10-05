# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_base64
# Purpose:      Identifies (best-effort) Base64-encoded strings in URLs.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     31/01/2017
# Copyright:   (c) Steve Micallef 2017
# -------------------------------------------------------------------------------

import base64
import re
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_base64(SpiderFootPlugin):

    meta = {
        'name': "Base64 Decoder",
        'summary': "Identify Base64-encoded strings in URLs, often revealing interesting hidden information.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

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

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL"]

    # What events this module produces
    def producedEvents(self):
        return ["BASE64_DATA"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        decoded_data = urllib.parse.unquote(eventData)

        # Note: this will miss base64 encoded strings with no padding
        # (strings which do not end with '=' or '==')
        pat = re.compile(r"([A-Za-z0-9+\/]+={1,2})")
        m = re.findall(pat, decoded_data)
        for match in m:
            if self.checkForStop():
                return

            minlen = int(self.opts['minlength'])
            if len(match) < minlen:
                continue

            # Base64-encoded strings don't look like normal strings
            caps = sum(1 for c in match if c.isupper())
            if caps < (minlen / 4):
                continue

            if isinstance(match, str):
                string = match
            else:
                string = str(match)

            self.info(f"Found Base64 string: {match}")

            try:
                string += f" ({base64.b64decode(match).decode('utf-8')})"
            except Exception as e:
                self.debug(f"Unable to base64-decode string: {e}")
                continue

            evt = SpiderFootEvent("BASE64_DATA", string, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_base64 class
