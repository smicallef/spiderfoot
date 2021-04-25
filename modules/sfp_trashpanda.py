# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_trashpanda
# Purpose:      Spiderfoot plugin to query Trashpanda - got-hacked.wtf API to gather intelligence about
#               mentions of your target in paste sites like Pastebin, Ghostbin and Zeropaste
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     17/04/2021
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import base64
import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_trashpanda(SpiderFootPlugin):

    meta = {
        'name': "Trashpanda",
        'summary': "Queries Trashpanda to gather intelligence about mentions of target in pastesites",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Leaks, Dumps and Breaches"],
        'dataSource': {
            'website': "https://got-hacked.wtf",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "http://api.got-hacked.wtf:5580/help"
            ],
            'apiKeyInstructions': [
                "Follow the guide at https://got-hacked.wtf/"
            ],
            'favIcon': "https://got-hacked.wtf/wp-content/uploads/2020/07/cropped-IMG_7619.jpg",
            'logo': "https://got-hacked.wtf/wp-content/uploads/2020/07/cropped-IMG_7619.jpg",
            'description': "The bot searches different paste sites for leaked credentials."
            "The API itself gives access to all unique credentials the bot ever detected.",
        }
    }

    # Default options
    opts = {
        'username': '',
        'password': '',
    }

    # Option descriptions
    optdescs = {
        'username': "Trashpanda API Username",
        'password': 'Trashpanda API Password',
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
            "INTERNET_NAME",
            "EMAILADDR"
        ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [
            "LEAKSITE_CONTENT",
            "LEAKSITE_URL",
            "PASSWORD_COMPROMISED",
        ]

    def query(self, qry, eventName):
        secret = self.opts['username'] + ':' + self.opts['password']
        auth = base64.b64encode(secret.encode('utf-8')).decode('utf-8')

        queryString = ""
        if eventName == "DOMAIN_NAME" or eventName == "INTERNET_NAME":
            queryString = f"http://api.got-hacked.wtf:5580/domain?v={qry}&s=zpg"
        elif eventName == "EMAILADDR":
            queryString = f"http://api.got-hacked.wtf:5580/email?v={qry}&s=zpg"

        headers = {
            'Accept': "application/json",
            'Authorization': f"Basic {auth}"
        }

        res = self.sf.fetchUrl(
            queryString,
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        if res['code'] != "200":
            self.sf.error("Error retrieving search results from Trashpanda(got-hacked.wtf)")
            return None

        return json.loads(res['content'])

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return None

        if self.opts['username'] == "" or self.opts['password'] == "":
            self.sf.error("You enabled sfp_trashpanda but did not set an API username / password!")
            self.errorState = True
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return None
        else:
            self.results[eventData] = True

        data = self.query(eventData, eventName)

        if data is None:
            return None

        leaksiteUrls = set()
        for row in data:
            evt = SpiderFootEvent("PASSWORD_COMPROMISED", f"{row.get('email')}:{row.get('password')} [{row.get('paste')}]", self.__name__, event)
            self.notifyListeners(evt)

            leaksiteUrls.add(row.get("paste"))

        for leaksiteUrl in leaksiteUrls:
            try:
                self.sf.debug("Found a link: " + leaksiteUrl)

                if self.checkForStop():
                    return None

                res = self.sf.fetchUrl(leaksiteUrl, timeout=self.opts['_fetchtimeout'],
                                       useragent=self.opts['_useragent'])

                if res['content'] is None:
                    self.sf.debug(f"Ignoring {leaksiteUrl} as no data returned")
                    continue

                # Sometimes pastes search results false positives
                if eventData.lower() not in str(res['content']).lower():
                    self.sf.debug("String not found in pastes content.")
                    continue

                if re.search(
                    r"[^a-zA-Z\-\_0-9]" + re.escape(eventData) + r"[^a-zA-Z\-\_0-9]",
                    res['content'],
                    re.IGNORECASE
                ) is None:
                    continue

                evt = SpiderFootEvent("LEAKSITE_URL", leaksiteUrl, self.__name__, event)
                self.notifyListeners(evt)

                evt = SpiderFootEvent("LEAKSITE_CONTENT", res['content'], self.__name__, evt)
                self.notifyListeners(evt)
            except Exception as e:
                self.sf.debug(f"Error while fetching leaksite content : {str(e)}")

# End of sfp_trashpanda class
