# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_snov
# Purpose:      Spiderfoot plugin to search Snov.IO API for emails
#               associated to target domain
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     16/05/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_snov(SpiderFootPlugin):

    meta = {
        'name': "Snov",
        'summary': "Gather available email IDs from identified domains",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://snov.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://snov.io/api"
            ],
            'apiKeyInstructions': [
                "Visit https://snov.io",
                "Register a free account",
                "Navigate to https://app.snov.io/api-setting",
                "The API key combination is listed under 'API User ID' and 'API Secret'"
            ],
            'favIcon': "https://snov.io/img/favicon/favicon-96x96.png",
            'logo': "https://cdn.snov.io/img/common/icon-logo.svg?cf6b11aa56fa13f6c94c969282424cfc",
            'description': "Snov.io API allows to get a list of all emails from a particular domain, "
            "find email addresses by name and domain, verify emails, add prospects to a list, "
            "change a recipient's status and more.",
        }
    }

    opts = {
        'api_key_client_id': '',
        'api_key_client_secret': ''
    }

    # Option descriptions. Delete any options not applicable to this module.
    optdescs = {
        'api_key_client_id': "Snov.io API Client ID",
        'api_key_client_secret': "Snov.io API Client Secret"
    }

    results = None
    errorState = False

    # More than 100 per response is not supported by Snov API
    limit = 100

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # For a list of all events, check sfdb.py.
    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["EMAILADDR", "EMAILADDR_GENERIC"]

    # Get Authentication token from Snov.IO API
    def queryAccessToken(self):
        params = {
            'grant_type': "client_credentials",
            'client_id': self.opts['api_key_client_id'],
            'client_secret': self.opts['api_key_client_secret']
        }

        headers = {
            'Accept': "application/json",
        }

        res = self.sf.fetchUrl(
            'https://api.snov.io/v1/oauth/access_token?' + urllib.parse.urlencode(params),
            headers=headers,
            timeout=30,
            useragent=self.opts['_useragent']
        )

        if res['code'] != '200':
            self.error("No access token received from snov.io for the provided Client ID and/or Client Secret")
            self.errorState = True
            return None
        try:
            # Extract access token from response
            content = res.get('content')
            accessToken = json.loads(content).get('access_token')

            if accessToken is None:
                self.error("No access token received from snov.io for the provided Client ID and/or Client Secret")
                return None

            return str(accessToken)
        except Exception:
            self.error("No access token received from snov.io for the provided Client ID and/or Client Secret")
            self.errorState = True
            return None

    # Fetch email addresses related to target domain
    def queryDomainName(self, qry, accessToken, currentLastId):
        params = {
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'access_token': accessToken,
            'type': "all",
            'limit': str(self.limit),
            'lastId': str(currentLastId)
        }

        headers = {
            'Accept': "application/json",
        }

        res = self.sf.fetchUrl(
            'https://api.snov.io/v2/domain-emails-with-info?' + urllib.parse.urlencode(params),
            headers=headers,
            timeout=30,
            useragent=self.opts['_useragent']
        )
        if res['code'] != '200':
            self.debug("Could not fetch email addresses")
            return None

        return res.get('content')

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Always check if the API key is set and complain if it isn't, then set
        # self.errorState to avoid this being a continual complaint during the scan.
        if self.opts['api_key_client_id'] == "" or self.opts['api_key_client_secret'] == "":
            self.error("You enabled sfp_snov but did not set a Client ID and/or Client Secret")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Get access token from Snov IO API
        accessToken = self.queryAccessToken()
        if accessToken is None or accessToken == '':
            self.error("No access token received from snov.io for the provided Client ID and/or Client Secret")
            self.errorState = True
            return

        currentLastId = 0
        nextPageHasData = True

        while nextPageHasData:
            if self.checkForStop():
                return

            data = self.queryDomainName(eventData, accessToken, currentLastId)
            if data is None:
                self.debug("No email address found for target domain")
                break

            try:
                data = json.loads(data)
            except Exception:
                self.debug("No email address found for target domain")
                break

            evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
            self.notifyListeners(evt)

            records = data.get('emails')
            lastId = data.get('lastId')

            if records:
                for record in records:
                    if record:
                        email = str(record.get('email'))
                        if email:
                            if email in self.results:
                                continue
                            if not self.sf.validEmail(email):
                                continue
                            self.results[email] = True

                            if email.split("@")[0] in self.opts['_genericusers'].split(","):
                                evttype = "EMAILADDR_GENERIC"
                            else:
                                evttype = "EMAILADDR"

                            evt = SpiderFootEvent(evttype, email, self.__name__, event)
                            self.notifyListeners(evt)

            # Determine whether another page of data exists
            if len(records) < self.limit:
                nextPageHasData = False
            currentLastId = lastId

# End of sfp_snov class
