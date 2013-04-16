#-------------------------------------------------------------------------------
# Name:         sfp_subdomain
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) and identifying sub-domains
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in __init__)
sf = None

class sfp_subdomain(SpiderFootPlugin):
    """ Identify hostnames / sub-domain names in URLs and obtained content. """
    # Default options
    opts = { }

    # Target
    baseDomain = None
    results = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["RAW_DATA", "LINKED_URL_INTERNAL"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event.sourceEvent

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        matches = re.findall("([a-zA-Z0-9\-\.]+\." + self.baseDomain + ")", eventData,
            re.IGNORECASE)
        if matches == None:
            return None

        for match in matches:
            # Skip URL encoded /
            if match.lower().startswith("2f"):
                continue

            sf.debug("Found sub-domain: " + match)
            if self.results.has_key(match):
                continue
            else:
                sf.info("New sub-domain/host found: " + match)
                evt = SpiderFootEvent("SUBDOMAIN", match, self.__name__, event)
                self.notifyListeners(evt)
                self.results[match] = True

        return None

# End of sfp_subdomain class
