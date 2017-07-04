# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_wikileaks
# Purpose:      Searches Wikileaks for mentions of domain names and e-mails.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     16/11/2016
# Copyright:   (c) Steve Micallef 2016
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import socket
import datetime
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_wikileaks(SpiderFootPlugin):
    """Wikileaks:Footprint,Investigate,Passive:Leaks, Dumps and Breaches:errorprone:Search Wikileaks for mentions of domain names and e-mail addresses."""


    # Default options
    opts = {
        'daysback': 365,
        'external': True
    }

    # Option descriptions
    optdescs = {
        'daysback': "How many days back to consider a leak valid for capturing. 0 = unlimited.",
        'external': "Include external leak sources such as Associated Twitter accounts, Snowden + Hammond Documents, Cryptome Documents, ICWatch, This Day in WikiLeaks Blog and WikiLeaks Press, WL Central."
    }

    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "EMAILADDR"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["LEAKSITE_CONTENT", "LEAKSITE_URL", "SEARCH_ENGINE_WEB_CONTENT"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results.append(eventData)

        if self.opts['external']:
            external = "True"
        else:
            external = ""

        if self.opts['daysback'] != None and self.opts['daysback'] != 0:
            newDate = datetime.datetime.now() - datetime.timedelta(days=int(self.opts['daysback']))
            maxDate = newDate.strftime("%Y-%m-%d")
        else:
            maxDate = ""

        wlurl = "https://search.wikileaks.org/?query=%22" + eventData + "%22" + \
              "&released_date_start=" + maxDate + "&include_external_sources=" + \
              external + "&new_search=True&order_by=most_relevant#results"
        res = self.sf.fetchUrl(wlurl)
        if res['content'] is None:
            self.sf.error("Unable to fetch Wikileaks content.", False)
            return None

        # Fetch the paste site content
        links = dict()
        links.update(self.sf.parseLinks(wlurl, res['content'], "wikileaks.org"))
        links.update(self.sf.parseLinks(wlurl, res['content'], "cryptome.org"))
        keepGoing = True
        page = 0
        while keepGoing:
            if "page=" not in res['content']:
                keepGoing = False

            valid = False
            for link in links:
                # We can safely skip search.wikileaks.org and others.
                if not link.startswith("https://wikileaks.org/") and not link.startswith("https://cryptome.org/"):
                    continue
                else:
                    self.sf.debug("Found a link: " + link)
                    if self.checkForStop():
                        return None
    
                    # Wikileaks leak links will have a nested folder structure link
                    if link.count('/') >= 4:
                        if not link.endswith(".js") and not link.endswith(".css"):
                            evt = SpiderFootEvent("LEAKSITE_URL", link, self.__name__, event)
                            self.notifyListeners(evt)
                            valid = True

            if valid:
                evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", res['content'], 
                                      self.__name__, event)
                self.notifyListeners(evt)

            # Fail-safe to prevent infinite looping
            if page > 50:
                break

            if keepGoing:
                page += 1
                wlurl = "https://search.wikileaks.org/?query=%22" + eventData + "%22" + \
                        "&released_date_start=" + maxDate + "&include_external_sources=" + \
                        external + "&new_search=True&order_by=most_relevant&page=" + \
                        str(page) + "#results"
                res = self.sf.fetchUrl(wlurl)
                # Fetch the paste site content
                links = dict()
                links.update(self.sf.parseLinks(wlurl, res['content'], "wikileaks.org"))
                links.update(self.sf.parseLinks(wlurl, res['content'], "cryptome.org"))

# End of sfp_wikileaks class
