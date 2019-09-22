# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_neutrinoapi
# Purpose:     SpiderFoot plug-in to search NeutrinoAPI for IP address info,
#              check IP address reputation, and search for phone location.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-11-30
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_neutrinoapi(SpiderFootPlugin):
    """NeutrinoAPI:Footprint,Investigate,Passive:Reputation Systems:apikey:Search NeutrinoAPI for IP address info and check IP reputation."""

    # Default options
    opts = {
        'user_id': '',
        'api_key': '',
        'timeout': 30
    }

    # Option descriptions
    optdescs = {
        'user_id': "NeutrinoAPI user ID.",
        'api_key': "NeutrinoAPI API key.",
        'timeout': "Query timeout, in seconds."
    }

    results = dict()
    errorState = False

    # Initialize module and module options
    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "NeutrinoAPI"
        self.results = dict()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'PHONE_NUMBER']

    # What events this module produces
    def producedEvents(self):
        return ['RAW_RIR_DATA', 'MALICIOUS_IPADDR', 'GEOINFO']

    # Query the phone-validate REST API
    # https://www.neutrinoapi.com/api/phone-validate/
    def queryPhoneValidate(self, qry):
        res = self.sf.fetchUrl('https://neutrinoapi.com/phone-validate',
            postData="output-format=json&number=" + qry + "&user-id=" + self.opts['user_id'] + "&api-key=" + self.opts['api_key'],
            timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        return self.parseApiResponse(res)

    # Query the ip-info REST API
    # https://www.neutrinoapi.com/api/ip-info/
    def queryIpInfo(self, qry):
        res = self.sf.fetchUrl("https://neutrinoapi.com/ip-info",
            postData="output-format=json&ip=" + qry + "&user-id=" + self.opts['user_id'] + "&api-key=" + self.opts['api_key'],
            timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        return self.parseApiResponse(res)

    # Query the ip-blocklist REST API
    # https://www.neutrinoapi.com/api/ip-blocklist/
    def queryIpBlocklist(self, qry):
        res = self.sf.fetchUrl("https://neutrinoapi.com/ip-blocklist",
            postData="output-format=json&ip=" + qry + "&user-id=" + self.opts['user_id'] + "&api-key=" + self.opts['api_key'],
            timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        return self.parseApiResponse(res)

    # Query the host-reputation REST API
    # https://www.neutrinoapi.com/api/host-reputation/
    def queryHostReputation(self, qry):
        res = self.sf.fetchUrl("https://neutrinoapi.com/host-reputation",
            postData="output-format=json&host=" + qry + "&user-id=" + self.opts['user_id'] + "&api-key=" + self.opts['api_key'],
            timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        return self.parseApiResponse(res)

    # Parse API response
    def parseApiResponse(self, res):
        if res['code'] == "403":
            self.sf.error("Authentication failed", False)
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        if res['code'] == "400":
            if data.get('api-error-msg'):
                self.sf.error("Error: " + data.get('api-error-msg'), False)
            else:
                self.sf.error("Error: HTTP 400", False)
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if eventData in self.results:
            return None

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_neutrinoapi but did not set an API key!", False)
            self.errorState = True
            return None

        if self.opts['user_id'] == "":
            self.sf.error("You enabled sfp_neutrinoapi but did not set a user ID!", False)
            self.errorState = True
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventName == 'PHONE_NUMBER':
            data = self.queryPhoneValidate(eventData)

            if data is None:
                self.sf.debug("No phone info results found for " + eventData)
            else:
                if data.get('location') is not None and data.get('country') is not None:
                    if data.get('location') == data.get('country'):
                        location = data.get('location')
                    else:
                        location = data.get('location') + ', ' + data.get('country')

                    evt = SpiderFootEvent("GEOINFO", location, self.__name__, event)
                    self.notifyListeners(evt)
                    evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
                    self.notifyListeners(evt)


        if eventName == 'IP_ADDRESS':
            data = self.queryIpInfo(eventData)

            if data is None:
                self.sf.debug("No IP info results found for " + eventData)
            else:
                if data.get('city') is not None and data.get('region') is not None and data.get('country-code') is not None:
                    location = data.get('city') + ', ' + data.get('region') + ', ' + data.get('country-code')
                    evt = SpiderFootEvent("GEOINFO", location, self.__name__, event)
                    self.notifyListeners(evt)

            data = self.queryIpBlocklist(eventData)

            if data is None:
                self.sf.debug("No IP blocklist results found for " + eventData)
            else:
                if data.get('is-listed'):
                    evt = SpiderFootEvent("MALICIOUS_IPADDR", "NeutrinoAPI [" + eventData + "]", self.__name__, event)
                    self.notifyListeners(evt)
                    evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
                    self.notifyListeners(evt)

            data = self.queryHostReputation(eventData)

            if data is None:
                self.sf.debug("No host reputation results found for " + eventData)
            else:
                if data.get('is-listed'):
                    evt = SpiderFootEvent("MALICIOUS_IPADDR", "NeutrinoAPI [" + eventData + "]", self.__name__, event)
                    self.notifyListeners(evt)
                    evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_neutrinoapi class
