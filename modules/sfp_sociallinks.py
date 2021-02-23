# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_sociallinks
# Purpose:      Spiderfoot plugin to query mtg-bi.com to gather intelligence from
#               social media platforms and dark web
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     20/02/2021
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_sociallinks(SpiderFootPlugin):

    meta = {
        'name': "Social Links",
        'summary': "Queries mtg-bi.com to gather intelligence from social media platforms and dark web",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://mtg-bi.com/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://docs.osint.rest/"
            ],
            'favIcon': "https://seon.io/assets/favicons/favicon-16x16.png",
            'logo': "https://seon.io/assets/favicons/apple-touch-icon-152.png",
            'description': "Social Links provides instruments for OSINT methods "
            "that are used by the world's leading investigation and law enforcement agencies",
        }
    }

    # Default options
    opts = {
        'api_key': '',
    }

    # Option descriptions
    optdescs = {
        'api_key': "API Key for mtg-bi.com",
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
            "USERNAME",
            "EMAILADDR",
            "PHONE_NUMBER"
        ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [
            "GEOINFO",
            "SOCIAL_MEDIA",
            "HUMAN_NAME",
            "JOB_TITLE",
            "RAW_RIR_DATA"
        ]

    def queryTelegram(self, qry, eventName):
        if eventName == "PHONE_NUMBER":
            queryString = f"https://osint.rest/api/telegram/user_by_phone?query={qry}"
        elif eventName == "USERNAME":
            queryString = f"https://osint.rest/api/telegram/user_by_alias?query={qry}"

        headers = {
            'Accept': "application/json",
            'Authorization': self.opts['api_key']
        }

        res = self.sf.fetchUrl(
            queryString,
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        return json.loads(res['content'])

    def queryFlickr(self, qry, eventName):
        if eventName == "EMAILADDR":
            queryString = f"https://osint.rest/api/flickr/email?email={qry}"

        headers = {
            'Accept': "application/json",
            'Authorization': self.opts['api_key']
        }

        res = self.sf.fetchUrl(
            queryString,
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        return json.loads(res['content'])
    
    def querySkype(self, qry, eventName):
        if eventName == "EMAILADDR":
            queryString = f"https://osint.rest/api/skype/search/v2?query={qry}"

        headers = {
            'Accept': "application/json",
            'Authorization': self.opts['api_key']
        }

        res = self.sf.fetchUrl(
            queryString,
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        return json.loads(res['content'])

    def queryLinkedin(self, qry, eventName):
        if eventName == "EMAILADDR":
            queryString = f"https://osint.rest/api/linkedin/lookup_by_email/v2?query={qry}"

        headers = {
            'Accept': "application/json",
            'Authorization': self.opts['api_key']
        }

        res = self.sf.fetchUrl(
            queryString,
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        return json.loads(res['content'])

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_sociallinks but did not set an API key!")
            self.errorState = True
            return

        if self.errorState:
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return None
        else:
            self.results[eventData] = True

# End of sfp_sociallinks class
