# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_skymem
# Purpose:      SpiderFoot plug-in for retrieving up to 100 e-mail addresses
#               belonging to your target from Skymem.
#
# Author:      <bcoles@gmail.com>
#
# Created:     29/09/2018
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_skymem(SpiderFootPlugin):
    """Skymem:Footprint,Investigate,Passive:Search Engines::Look up e-mail addresses on Skymem."""


    results = dict()

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "Skymem"
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["EMAILADDR"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Get e-mail addresses on this domain
        res = self.sf.fetchUrl("http://www.skymem.info/srch?q=" + eventData, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            return None

        # Extract emails from results page
        pat = re.compile("([a-zA-Z\.0-9_\-]+@[a-zA-Z\.0-9\-]+\.[a-zA-Z\.0-9\-]+)")
        matches = re.findall(pat, res['content'])
        if not matches:
            return None

        for match in matches:
            self.sf.debug("Found possible email: " + match)

            # Handle false positive matches
            if len(match) < 5:
                self.sf.debug("Likely invalid address.")
                continue

            # Handle messed up encodings
            if "%" in match:
                self.sf.debug("Skipped address: " + match)
                continue

            # Skip unrelated emails
            mailDom = match.lower().split('@')[1]
            if not self.getTarget().matches(mailDom):
                self.sf.debug("Skipped address: " + match)
                continue

            self.sf.info("Found e-mail address: " + match)
            if match not in self.results:
                evt = SpiderFootEvent("EMAILADDR", match, self.__name__, event)
                self.notifyListeners(evt)
                self.results[match] = True

        # Loop through first 20 pages of results
        domain_ids = re.findall(r'<a href="/domain/([a-z0-9]+)\?p=', res['content'])

        if not domain_ids:
            return None

        domain_id = domain_ids[0]

        for page in range(1, 21):
            res = self.sf.fetchUrl("http://www.skymem.info/domain/" + domain_id + "?p=" + str(page), timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

            if res['content'] is None:
                break

            pat = re.compile("([a-zA-Z\.0-9_\-]+@[a-zA-Z\.0-9\-]+\.[a-zA-Z\.0-9\-]+)")
            matches = re.findall(pat, res['content'])
            for match in matches:
                self.sf.debug("Found possible email: " + match)

                # Handle false positive matches
                if len(match) < 5:
                    self.sf.debug("Likely invalid address.")
                    continue

                # Handle messed up encodings
                if "%" in match:
                    self.sf.debug("Skipped address: " + match)
                    continue

                # Skip unrelated emails
                mailDom = match.lower().split('@')[1]
                if not self.getTarget().matches(mailDom):
                    self.sf.debug("Skipped address: " + match)
                    continue

                self.sf.info("Found e-mail address: " + match)
                if match not in self.results:
                    evt = SpiderFootEvent("EMAILADDR", match, self.__name__, event)
                    self.notifyListeners(evt)
                    self.results[match] = True

            # Check if we're on the last page of results
            max_page = 0
            pages = re.findall(r'/domain/' + domain_id + '\?p=(\d+)', res['content'])
            for p in pages:
                if int(p) >= max_page:
                    max_page = int(p)
            if page >= max_page:
                break

        return None

# End of sfp_skymem class
