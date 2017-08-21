# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_crossref
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
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_crossref(SpiderFootPlugin):
    """Cross-Reference:Footprint:Crawling and Scanning::Identify whether other domains are associated ('Affiliates') of the target."""


    # Default options
    opts = {
        'checkbase': True
    }

    # Option descriptions
    optdescs = {
        "checkbase": "Check the base URL of the potential affiliate if no direct affiliation found?"
    }

    # Internal results tracking
    results = dict()
    fetched = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.fetched = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['LINKED_URL_EXTERNAL', 'SIMILARDOMAIN', 
                'CO_HOSTED_SITE', 'DARKNET_MENTION_URL']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["AFFILIATE_INTERNET_NAME", "AFFILIATE_WEB_CONTENT"]

    # Handle events sent to this module
    # In this module's case, eventData will be the URL or a domain which
    # was found in some content somewhere.
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # The SIMILARDOMAIN and CO_HOSTED_SITE events supply domains, 
        # not URLs. Assume HTTP.
        if eventName in ['SIMILARDOMAIN', 'CO_HOSTED_SITE']:
            eventData = 'http://' + eventData.lower()

        # We are only interested in external sites for the crossref
        if self.getTarget().matches(self.sf.urlFQDN(eventData)):
            self.sf.debug("Ignoring " + eventData + " as not external")
            return None

        if eventData in self.fetched:
            self.sf.debug("Ignoring " + eventData + " as already tested")
            return
        else:
            self.fetched.append(eventData)

        self.sf.debug("Testing for affiliation: " + eventData)
        res = self.sf.fetchUrl(eventData, timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.debug("Ignoring " + eventData + " as no data returned")
            return None

        matched = False
        for name in self.getTarget().getNames():
            # Search for mentions of our host/domain in the external site's data
            pat = re.compile("([\.\'\/\"\ ]" + name + "[\.\'\/\"\ ])", re.IGNORECASE)
            matches = re.findall(pat, res['content'])

            if len(matches) > 0:
                matched = True
                url = eventData
                break

        if not matched:
            # If the name wasn't found in the affiliate, and checkbase is set,
            # fetch the base URL of the affiliate to check for a crossref.
            if eventName == "LINKED_URL_EXTERNAL" and self.opts['checkbase']:
                # Check the base url to see if there is an affiliation
                url = self.sf.urlBaseUrl(eventData)
                if url in self.fetched:
                    return None
                else:
                    self.fetched.append(url)

                res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])
                if res['content'] is not None:
                    for name in self.getTarget().getNames():
                        pat = re.compile("([\.\'\/\"\ ]" + name + "[\'\/\"\ ])",
                                         re.IGNORECASE)
                        matches = re.findall(pat, res['content'])

                        if len(matches) > 0:
                            matched = True

        if matched:
            if not event.moduleDataSource:
                event.moduleDataSource = "Unknown"
            self.sf.info("Found affiliate: " + url)
            evt1 = SpiderFootEvent("AFFILIATE_INTERNET_NAME", self.sf.urlFQDN(url),
                                   self.__name__, event)
            evt1.moduleDataSource = event.moduleDataSource
            self.notifyListeners(evt1)
            evt2 = SpiderFootEvent("AFFILIATE_WEB_CONTENT", res['content'],
                                   self.__name__, evt1)
            evt2.moduleDataSource = event.moduleDataSource
            self.notifyListeners(evt2)

# End of sfp_crossref class
