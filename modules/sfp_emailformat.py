# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_emailformat
# Purpose:      SpiderFoot plug-in for retrieving e-mail addresses
#               belonging to your target from email-format.com.
#
# Author:      <bcoles@gmail.com>
#
# Created:     29/09/2018
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from bs4 import BeautifulSoup

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_emailformat(SpiderFootPlugin):

    meta = {
        'name': "EmailFormat",
        'summary': "Look up e-mail addresses on email-format.com.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.email-format.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.email-format.com/i/api_access/",
                "https://www.email-format.com/i/api_v2/",
                "https://www.email-format.com/i/api_v1/"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://www.email-format.com/",
            'logo': "https://www.google.com/s2/favicons?domain=https://www.email-format.com/",
            'description': "Save time and energy - find the email address formats in use at thousands of companies.",
        }
    }

    opts = {
    }

    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['INTERNET_NAME', "DOMAIN_NAME"]

    def producedEvents(self):
        return ["EMAILADDR", "EMAILADDR_GENERIC"]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Get e-mail addresses on this domain
        res = self.sf.fetchUrl(f"https://www.email-format.com/d/{eventData}/", timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            return

        html = BeautifulSoup(res["content"], features="lxml")
        if not html:
            return

        tbody = html.find('tbody')
        if tbody:
            data = str(tbody.contents)
        else:
            # fall back to raw page contents
            data = res["content"]

        emails = self.sf.parseEmails(data)
        for email in emails:
            # Skip unrelated emails
            mailDom = email.lower().split('@')[1]
            if not self.getTarget().matches(mailDom):
                self.debug(f"Skipped address: {email}")
                continue

            # Skip masked emails
            if re.match(r"^[0-9a-f]{8}\.[0-9]{7}@", email):
                self.debug(f"Skipped address: {email}")
                continue

            self.info(f"Found e-mail address: {email}")
            if email.split("@")[0] in self.opts['_genericusers'].split(","):
                evttype = "EMAILADDR_GENERIC"
            else:
                evttype = "EMAILADDR"

            evt = SpiderFootEvent(evttype, email, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_emailformat class
