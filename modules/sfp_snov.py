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

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
from netaddr import IPNetwork
import urllib.request, urllib.parse, urllib.error
import json

class sfp_snov(SpiderFootPlugin):
    """Snov:Investigate,Passive:Reputation Systems:client_id,client_secret:Gather available email ids from target domain"""

    opts = {
        'client_id': '',
        'client_secret': ''
    }

    # Option descriptions. Delete any options not applicable to this module.
    optdescs = {
        'client_id': "Client ID for snov.io API",
        'client_secret': "Client Secret for snov.io API"
    }

    results = None
    errorState = False  

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
        return ["EMAILADDR"]
    
    # Get Authentication token from Snov.IO API
    def queryAccessToken(self):
        params = {
            'grant_type': "client_credentials",
            'client_id': self.opts['client_id'],
            'client_secret': self.opts['client_secret']
        }

        headers = {
            'Accept': "application/json",
        }
        
        res = self.sf.fetchUrl(
            'https://api.snov.io/v1/oauth/access_token?' + urllib.parse.urlencode(params),
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        if not res['code'] == '200':
            self.sf.error("Could not authenticate credentials", False)
            self.errorState = True 
            return None
        try:
            # Extract access token from response
            accessToken = json.loads(res.get('content')).get('access_token')
            return str(accessToken)
        except Exception: 
            self.sf.debug("Could not fetch access token")
            self.errorState = True
            return None
        
    # Fetch email addresses related to target domain
    def queryDomainName(self, qry, accessToken, currentOffset):
        params = {
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'access_token': accessToken,
            'type': "all",
            'limit': str(self.limit),
            'offset': str(currentOffset)
        }

        headers = {
            'Accept' : "application/json",
        }

        res = self.sf.fetchUrl(
            'https://api.snov.io/v1/get-domain-emails-with-info',
            postData=params,
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        if not res['code'] == '200':
            self.sf.debug("Could not fetch email addresses")
            return None

        try:
            return res['content']
        except:
            self.sf.debug("Could not fetch email addresses")
            return None


    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        
        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Always check if the API key is set and complain if it isn't, then set
        # self.errorState to avoid this being a continual complaint during the scan.
        if self.opts['client_id'] == "" or self.opts['client_secret'] == "":
            self.sf.error("You enabled sfp_snov but did not set an client_id and/or client_secret", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        # Get access token from Snov IO API
        accessToken = self.queryAccessToken()
        if accessToken is None or accessToken == '':
            self.sf.debug("No access token received from Snov")
            self.errorState = True
            return None

        currentOffset = 0
        nextPageHasData = True

        while nextPageHasData:
            if self.checkForStop():
                return None

            data = self.queryDomainName(eventData, accessToken, currentOffset)
            
            if data is None:
                self.sf.debug("No email address found for target domain")
                return None

            if isinstance(data, str):
                data = json.loads(data.replace("null","None").replace("'","\""))
            
            evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
            self.notifyListeners(evt)

            records = data.get('emails')

            if isinstance(records, str):
                records = json.loads(records.replace("null","None").replace("'","\""))

            if records:
                for record in records:
                    if isinstance(record, str):
                        record = json.loads(record.replace("null","None").replace("'","\""))

                    if record:
                        email = record.get('email')
                        if email:
                            if email in self.results:
                                continue
                            self.results[email] = True

                            evt = SpiderFootEvent("EMAILADDR", str(email), self.__name__, event)
                            self.notifyListeners(evt)

            if len(records) < self.limit:
                nextPageHasData = False
            currentOffset += self.limit

        return None
# End of sfp_snov class
