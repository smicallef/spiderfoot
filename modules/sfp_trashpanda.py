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

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_trashpanda(SpiderFootPlugin):

    meta = {
        'name': "Trashpanda",
        'summary': "Queries got-hacked.wtf to gather intelligence about metions of target in pastesites",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://got-hacked.wtf",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "http://api.got-hacked.wtf:5580/help"
            ],
            'favIcon': "https://seon.io/assets/favicons/favicon-16x16.png",
            'logo': "https://got-hacked.wtf/wp-content/uploads/2020/07/cropped-IMG_7619.jpg",
            'description': "The bot searches different paste sites for leaked credentials."
            "The API itself gives access to all unique credentials the bot ever detected.",
        }
    }

    # Default options
    opts = {
        'api_key_username': '',
        'api_key_password': '',
    }

    # Option descriptions
    optdescs = {
        'api_key_username': "got-hacked.wtf API Key Username",
        'api_key_password': 'got-hacked.wtf API Key Password',
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
        secret = self.opts['api_key_username'] + ':' + self.opts['api_key_password']
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

        if self.opts['api_key_username'] == "" or self.opts['api_key_password'] == "":
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
            evt = SpiderFootEvent("LEAKSITE_URL", leaksiteUrl, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_trashpanda class
