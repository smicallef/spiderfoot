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

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_skymem(SpiderFootPlugin):

    meta = {
        'name': "Skymem",
        'summary': "Look up e-mail addresses on Skymem.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "http://www.skymem.info/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "http://www.skymem.info/faq"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=http://www.skymem.info/",
            'logo': "",
            'description': "Find email addresses of companies and people.",
        }
    }

    results = None

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['INTERNET_NAME', "DOMAIN_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["EMAILADDR", "EMAILADDR_GENERIC"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Get e-mail addresses on this domain
        res = self.sf.fetchUrl("http://www.skymem.info/srch?q=" + eventData, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            return

        # Extract emails from results page
        emails = self.sf.parseEmails(res['content'])

        for email in emails:
            # Skip unrelated emails
            mailDom = email.lower().split('@')[1]
            if not self.getTarget().matches(mailDom):
                self.debug("Skipped address: " + email)
                continue

            self.info("Found e-mail address: " + email)
            if email not in self.results:
                if email.split("@")[0] in self.opts['_genericusers'].split(","):
                    evttype = "EMAILADDR_GENERIC"
                else:
                    evttype = "EMAILADDR"
                evt = SpiderFootEvent(evttype, email, self.__name__, event)
                self.notifyListeners(evt)
                self.results[email] = True

        # Loop through first 20 pages of results
        domain_ids = re.findall(r'<a href="/domain/([a-z0-9]+)\?p=', str(res['content']))

        if not domain_ids:
            return

        domain_id = domain_ids[0]

        for page in range(1, 21):
            res = self.sf.fetchUrl("http://www.skymem.info/domain/" + domain_id + "?p=" + str(page), timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

            if res['content'] is None:
                break

            emails = self.sf.parseEmails(res['content'])
            for email in emails:
                # Skip unrelated emails
                mailDom = email.lower().split('@')[1]
                if not self.getTarget().matches(mailDom):
                    self.debug("Skipped address: " + email)
                    continue

                self.info("Found e-mail address: " + email)
                if email not in self.results:
                    if email.split("@")[0] in self.opts['_genericusers'].split(","):
                        evttype = "EMAILADDR_GENERIC"
                    else:
                        evttype = "EMAILADDR"
                    evt = SpiderFootEvent(evttype, email, self.__name__, event)
                    self.notifyListeners(evt)
                    self.results[email] = True

            # Check if we're on the last page of results
            max_page = 0
            pages = re.findall(r'/domain/' + domain_id + r'\?p=(\d+)', str(res['content']))
            for p in pages:
                if int(p) >= max_page:
                    max_page = int(p)
            if page >= max_page:
                break

# End of sfp_skymem class
