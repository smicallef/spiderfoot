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
from sflib import SpiderFoot, SpiderFootPlugin

# SpiderFoot standard lib (must be initialized in __init__)
sf = None

class sfp_subdomain(SpiderFootPlugin):
    """ Identify hostnames / sub-domain names in URLs and obtained content. """
    # Default options
    opts = {
        # These must always be set
        '__debug':       True,
        '__debugfilter': ''
    }

    # URL this instance is working on
    seedUrl = None
    baseDomain = None # calculated from the URL in __init__
    results = dict()

    def setup(self, url, userOpts=dict()):
        global sf
        self.seedUrl = url
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # For error reporting, debug, etc.
        sf = SpiderFoot(self.opts)

        # Extract the 'meaningful' part of the FQDN from the URL
        self.baseDomain = sf.urlBaseDom(self.seedUrl)
        sf.debug('Base Domain: ' + self.baseDomain)

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["WEBCONTENT", "URL"]

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventData):
        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        matches = re.findall("([a-zA-Z0-9\-\.]+\." + self.baseDomain + ")", eventData,
            re.IGNORECASE)
        if matches == None:
            return None

        for match in matches:
            # Skip URL encoded /
            if match.startswith("2F") or match.startswith("2f"):
                continue

            sf.debug("Found sub-domain: " + match)
            if self.results.has_key(match):
                continue
            else:
                self.notifyListeners("SUBDOMAIN", eventSource, match)
                self.results[match] = True

        return None

# End of sfp_subdomain class

if __name__ == '__main__':
    print "This module cannot be run stand-alone."
    exit(-1)
