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

import datetime

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_wikileaks(SpiderFootPlugin):

    meta = {
        'name': "Wikileaks",
        'summary': "Search Wikileaks for mentions of domain names and e-mail addresses.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://wikileaks.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://wikileaks.org/-Leaks-.html#submit",
                "https://wikileaks.org/What-is-WikiLeaks.html"
            ],
            'favIcon': "https://wikileaks.org/IMG/favicon.ico",
            'logo': "https://wikileaks.org/IMG/favicon.ico",
            'description': "WikiLeaks specializes in the analysis and publication of large datasets of censored "
            "or otherwise restricted official materials involving war, spying and corruption. "
            "It has so far published more than 10 million documents and associated analyses.",
        }
    }

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

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "EMAILADDR", "HUMAN_NAME"]

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

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if self.opts['external']:
            external = "True"
        else:
            external = ""

        if self.opts['daysback'] is not None and self.opts['daysback'] != 0:
            newDate = datetime.datetime.now() - datetime.timedelta(days=int(self.opts['daysback']))
            maxDate = newDate.strftime("%Y-%m-%d")
        else:
            maxDate = ""

        qdata = eventData.replace(" ", "+")
        wlurl = "query=%22" + qdata + "%22" + "&released_date_start=" + maxDate + "&include_external_sources=" + external + "&new_search=True&order_by=most_relevant#results"

        res = self.sf.fetchUrl(
            "https://search.wikileaks.org/?" + wlurl
        )
        if res['content'] is None:
            self.error("Unable to fetch Wikileaks content.")
            return

        # Fetch the paste site content
        links = dict()
        p = self.sf.parseLinks(wlurl, res['content'], "wikileaks.org")
        if p:
            links.update(p)

        p = self.sf.parseLinks(wlurl, res['content'], "cryptome.org")
        if p:
            links.update(p)

        keepGoing = True
        page = 0
        while keepGoing:
            if not res['content']:
                break

            if "page=" not in res['content']:
                keepGoing = False

            valid = False
            for link in links:
                if "search.wikileaks.org/" in link:
                    continue

                # We can safely skip search.wikileaks.org and others.
                if "wikileaks.org/" not in link and "cryptome.org/" not in link:
                    continue
                else:
                    self.debug("Found a link: " + link)
                    if self.checkForStop():
                        return

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
                wlurl = "https://search.wikileaks.org/?query=%22" + qdata + "%22" + \
                        "&released_date_start=" + maxDate + "&include_external_sources=" + \
                        external + "&new_search=True&order_by=most_relevant&page=" + \
                        str(page) + "#results"
                res = self.sf.fetchUrl(wlurl)
                if not res['content']:
                    break

                # Fetch the paste site content
                links = dict()
                p = self.sf.parseLinks(wlurl, res['content'], "wikileaks.org")
                if p:
                    links.update(p)

                p = self.sf.parseLinks(wlurl, res['content'], "cryptome.org")
                if p:
                    links.update(p)

# End of sfp_wikileaks class
