#-------------------------------------------------------------------------------
# Name:         sfp_xref
# Purpose:      SpiderFoot plug-in for scanning links identified from the
#               spidering process, and for external links, fetching them to
#               see if those sites link back to the original site, indicating a
#               potential relationship between the external sites.
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

class sfp_xref(SpiderFootPlugin):
    # Default options
    opts = {
        # These must always be set
        '_debug':       True,
        '_debugfilter': '',
        'checkbase':    True # Also check the base URL for a relationship if
                             # the link contains no xref
    }

    # Internal results tracking
    results = dict()

    # URL this instance is working on
    seedUrl = None
    baseDomain = None # calculated from the URL in __init__

    def __init__(self, url, userOpts=dict()):
        global sf
        self.seedUrl = url

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # For error reporting, debug, etc.
        sf = SpiderFoot(self.opts)

        # Extract the 'meaningful' part of the FQDN from the URL
        self.baseDomain = sf.urlBaseDom(self.seedUrl)
        sf.debug('Base Domain: ' + self.baseDomain)

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["URL", "SIMILARDOMAIN"]

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventData):
        sf.debug("Received event, " + eventName + ", from " + srcModuleName)
        # In this module's case, eventData will be the URL

        # We are only interested in external sites for the xref
        if sf.urlBaseDom(eventData) == self.baseDomain:
            sf.debug("Ignoring " + eventData + " as not external")
            return None

        res = sf.fetchUrl(eventData)
        if res['content'] == None:
            sf.debug("Ignoring " + eventData + " as no data returned")
            return None

        matches = re.findall("(" + self.baseDomain + ")", res['content'],
            re.IGNORECASE)
        if matches != None:
            for match in matches:
                if results.has_key(eventData):
                    continue

                results[eventData] = True
                sf.debug("Found affiliate: " + eventData)
                self.notifyListeners("AFFILIATE", eventSource, eventData)
        else:
            # As no xref was found on the main link, check the base url
            if this.opts['checkbase']:
                res = sf.fetchUrl(sf.urlBaseUrl(eventData))

        return None

# End of sfp_xref class

if __name__ == '__main__':
    print "This module cannot be run stand-alone."
    exit(-1)
