# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_metadefender
# Purpose:     Search MetaDefender API for IP address and domain reputation.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-09-21
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_metadefender(SpiderFootPlugin):
    """MetaDefender:Footprint,Investigate,Passive:Reputation Systems:apikey:Search MetaDefender API for IP address and domain IP reputation."""

    # Default options
    opts = {
        'api_key': '',
        # 10 requests / minute for free users
        # 100 requests / minute for paid users
        'delay': 6
    }

    # Option descriptions
    optdescs = {
        'api_key': 'MetaDefender API key.',
        'delay': 'Delay between requests, in seconds.'
    }

    results = None
    errorState = False

    # Initialize module and module options
    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'INTERNET_NAME']

    # What events this module produces
    def producedEvents(self):
        return ['MALICIOUS_IPADDR', 'MALICIOUS_INTERNET_NAME', 'GEOINFO']

    # Query domain REST API
    # https://onlinehelp.opswat.com/mdcloud/4.5_Domain_Reputation.html
    def queryDomain(self, qry):
        headers = {
            'Accept': 'application/json',
            'apikey': self.opts['api_key']
        }
        res = self.sf.fetchUrl('https://api.metadefender.com/v4/domain/' + qry,
                               headers=headers,
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query ip REST API
    # https://onlinehelp.opswat.com/mdcloud/4.1_IP_Reputation.html
    def queryIp(self, qry):
        headers = {
            'Accept': 'application/json',
            'apikey': self.opts['api_key']
        }
        res = self.sf.fetchUrl('https://api.metadefender.com/v4/ip/' + qry,
                               headers=headers,
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Parse API response
    def parseApiResponse(self, res):
        if res['code'] == "401":
            self.sf.error("Invalid MetaDefender API key", False)
            self.errorState = True
            return None

        # https://onlinehelp.opswat.com/mdcloud/3._Rate_Limiting.html
        # https://onlinehelp.opswat.com/mdcloud/4._Throttling.html
        if res['code'] == "429":
            self.sf.error("You are being rate-limited by MetaDefender", False)
            self.errorState = True
            return None

        if res['code'] == "404":
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
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
            self.sf.error("You enabled sfp_metadefender but did not set an API key!", False)
            self.errorState = True
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventName == 'IP_ADDRESS':
            data = self.queryIp(eventData)

            if data is None:
                self.sf.debug("No matches found for " + eventData)
                return None

            geo_info = data.get('geo_info')

            if geo_info:
                location = ', '.join(filter(None, [geo_info.get('city').get('name'), geo_info.get('country').get('name')]))
                evt = SpiderFootEvent('GEOINFO', location, self.__name__, event)
                self.notifyListeners(evt)

            res = data.get('lookup_results')

            if not res:
                self.sf.debug("No matches found for " + eventData)
                return None

            sources = res.get('sources')

            if not sources:
                self.sf.debug("No matches found for " + eventData)
                return None

            for m in sources:
                if m.get('assessment'):
                    provider = m.get('provider')
                    evt = SpiderFootEvent('MALICIOUS_IPADDR', provider + ' [' + eventData + ']', self.__name__, event)
                    self.notifyListeners(evt)

        if eventName == 'INTERNET_NAME':
            data = self.queryDomain(eventData)

            if data is None:
                self.sf.debug("No matches found for " + eventData)
                return None

            res = data.get('lookup_results')

            if not res:
                self.sf.debug("No matches found for " + eventData)
                return None

            sources = res.get('sources')

            if not sources:
                self.sf.debug("No matches found for " + eventData)
                return None

            for m in sources:
                if m.get('assessment'):
                    provider = m.get('provider')
                    evt = SpiderFootEvent('MALICIOUS_INTERNET_NAME', provider + ' [' + eventData + ']', self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_metadefender class
