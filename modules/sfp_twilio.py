# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_twilio
# Purpose:      Extract data from phone numbers.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     14/06/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
import base64
import json

class sfp_twilio(SpiderFootPlugin):
    """Twilio:Footprint,Investigate,Passive:Search Engines:apikey:Obtain information from Twilio about phone numbers. Ensure you have the Caller Name add-on installed in Twilio."""
    
    opts = {
        'api_key_account_sid': '',
        'api_key_auth_token': ''
    }

    optdescs = {
        'api_key_account_sid': 'Twilio Account SID',
        'api_key_auth_token': 'Twilio Auth Token'
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["PHONE_NUMBER"]

    # What events this module produces
    def producedEvents(self):
        return ["COMPANY_NAME", "RAW_RIR_DATA"]

    # When querying third parties, it's best to have a dedicated function
    # to do so and avoid putting it in handleEvent()
    def queryPhoneNumber(self, phoneNumber):   
        
        token = (base64.b64encode(self.opts['api_key_account_sid'].encode('utf8') + ":".encode('utf-8') + self.opts['api_key_auth_token'].encode('utf-8'))).decode('utf-8')

        headers = {
            'Accept': "application/json",
            'Authorization': "Basic " + token
        }

        res = self.sf.fetchUrl(
          'https://lookups.twilio.com/v1/PhoneNumbers/' + phoneNumber + "?Type=caller-name",
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        if res['code'] == '400':
            self.sf.error("Bad request.", False)
            return None
        
        if res['code'] == '404':
            self.sf.debug("Phone number not found.")
            return None
        
        if res['code'] == '429':
            self.sf.error("API usage limit reached.", False)
            return None

        if res['code'] == '503':
            self.sf.error("Service unavailable.", False)
            return None

        if not res['code'] == '200':
            self.sf.error("Could not fetch data.", False)
            return None

        return res.get('content')

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        # Always check if the API key is set and complain if it isn't, then set
        # self.errorState to avoid this being a continual complaint during the scan.
        if self.opts['api_key_account_sid'] == "" or self.opts['api_key_auth_token'] == "":
            self.sf.error("You enabled sfp_twilio but did not set account sid/auth token", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        content = self.queryPhoneNumber(eventData)
        
        if content is None:
            return None
        
        data = json.loads(content)

        evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)
        
        callerName = data.get('caller_name')
        if callerName:
            callerName = callerName.get('caller_name')
        
        if callerName:
            evt = SpiderFootEvent("COMPANY_NAME", callerName, self.__name__, event)
            self.notifyListeners(evt)   

        return None
        
# End of sfp_twilio class
