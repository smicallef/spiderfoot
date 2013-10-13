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
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_xref(SpiderFootPlugin):
    """Cross-Reference:Identify whether other domains are associated ('Affiliates') of the target."""

    # Default options
    opts = {
        'forcebase':    True, # Check the base URL for a link back to the seed
                              # domain in order to be considered a valid xref
        'checkbase':    True, # Only check the base URL for a relationship if
                              # the link provided contains no xref
        'checkcontent': True  # Submit affiliate content for other modules to
                              # analyze
    }

    # Option descriptions
    optdescs = {
        "forcebase":    "Require the base domain of an external URL for affiliation?",
        "checkbase":    "Check the base domain of a URL for affiliation?",
        "checkcontent": "Submit the affiliate content to other modules for analysis?"
    }

    # Internal results tracking
    results = dict()
    fetched = list()

    # Target
    baseDomain = None

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = dict()
        self.fetched = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['LINKED_URL_EXTERNAL', 'SIMILARDOMAIN']

    # Handle events sent to this module
    # In this module's case, eventData will be the URL or a domain which
    # was found in some content somewhere.
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # The SIMILARDOMAIN event supplies domains, not URLs. Assume HTTP.
        if eventName == 'SIMILARDOMAIN':
            eventData = 'http://'+ eventData.lower()

        # We are only interested in external sites for the xref
        if sf.urlBaseUrl(eventData).endswith(self.baseDomain):
            sf.debug("Ignoring " + eventData + " as not external")
            return None

        # If forcebase is set, we don't bother checking the URL from the event,
        # just it's base URL.
        if self.opts['forcebase']:
            url = sf.urlBaseUrl(eventData)
        else:
            url = eventData

        if url in self.fetched:
            sf.debug("Ignoring " + url + " as already tested")
            return

        sf.debug("Testing for affiliation: " + url)
        res = sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
            useragent=self.opts['_useragent'])
        self.fetched.append(url)

        if res['content'] == None:
            sf.debug("Ignoring " + url + " as no data returned")
            return None

        # Search for mentions of our domain in the external site's data
        matches = re.findall("([\.\'\/\"\ ]" + self.baseDomain + "[\.\'\/\"\ ])", 
            res['content'], re.IGNORECASE)

        # If the domain wasn't found in the affiliate, and checkbase is set,
        # fetch the base URL of the affiliate to check for a xref. Don't bother
        # if forcebase was set, as we would've already checked that anyway.
        if not self.opts['forcebase'] and len(matches) > 0 and self.opts['checkbase']:
            # Check the base url to see if there is an affiliation
            url = sf.urlBaseUrl(eventData)
            res = sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
                useragent=self.opts['_useragent'])
            if res['content'] != None:
                matches = re.findall("([\.\'\/\"\ ]" + self.baseDomain + "[\'\/\"\ ])", 
                    res['content'], re.IGNORECASE)
            else:
                return None

        if len(matches) > 0:
            if self.results.has_key(url):
                return None

            self.results[url] = True
            sf.info("Found affiliate: " + url)
            evt1 = SpiderFootEvent("AFFILIATE", url, self.__name__, event)
            self.notifyListeners(evt1)
            if self.opts['checkcontent']:
                evt2 = SpiderFootEvent("RAW_DATA", res['content'], self.__name__, evt1)
                self.notifyListeners(evt2)

        return None

# End of sfp_xref class
