# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_neutrinoapi
# Purpose:     SpiderFoot plug-in to search Apility API for IP address and domain
#              reputation.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-09-16
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_apility(SpiderFootPlugin):

    meta = {
        'name': "Apility",
        'summary': "Search Apility API for IP address and domain reputation.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://auth0.com/signals",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://auth0.com/signals/docs/"
            ],
            'apiKeyInstructions': [
                "Visit https://auth0.com",
                "Register a free account",
                "Navigate to https://manage.auth0.com/dashboard/",
                "Click on 'API'",
                "The API key is listed under 'Auth0 Management API'"
            ],
            'favIcon': "https://cdn.auth0.com/styleguide/components/1.0.8/media/logos/img/favicon.png",
            'logo': "https://auth0.com/signals/docs/images/signals-docs-logo.svg",
            'description': "Malicious login traffic is detected with Auth0’s Anomaly Detection engine. "
            "This helps protect our customers from automated attacks, such as credential stuffing.",
        }
    }

    # Default options
    opts = {
        'api_key': '',
        'delay': 2,
        'malicious_freemail': True
    }

    # Option descriptions
    optdescs = {
        'api_key': 'Apility API key.',
        'delay': 'Delay between requests, in seconds.',
        'malicious_freemail': 'Consider free mail servers to be malicious.'
    }

    results = None
    errorState = False

    # Initialize module and module options
    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'INTERNET_NAME']

    # What events this module produces
    def producedEvents(self):
        return [
            'MALICIOUS_IPADDR',
            'MALICIOUS_INTERNET_NAME',
            'IP_ADDRESS',
            'INTERNAL_IP_ADDRESS',
            'PROVIDER_MAIL',
            'PROVIDER_DNS',
            'RAW_RIR_DATA'
        ]

    # Query baddomain REST API
    # https://apility.io/apidocs/#domain-check
    def queryBadDomain(self, qry):
        headers = {
            'Accept': 'application/json',
            'X-Auth-Token': self.opts['api_key']
        }
        res = self.sf.fetchUrl('https://api.apility.net/baddomain/' + qry,
                               headers=headers,
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query badip REST API
    # https://apility.io/apidocs/#ip-check
    def queryBadIp(self, qry):
        headers = {
            'Accept': 'application/json',
            'X-Auth-Token': self.opts['api_key']
        }
        res = self.sf.fetchUrl('https://api.apility.net/badip/' + qry,
                               headers=headers,
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query IP REST API
    # https://apility.io/apidocs/#full-ip-address-reputation
    # Note: currently unused
    def queryIp(self, qry):
        headers = {
            'Accept': 'application/json',
            'X-Auth-Token': self.opts['api_key']
        }
        res = self.sf.fetchUrl('https://api.apility.net/v2.0/ip/' + qry,
                               headers=headers,
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query AS IP REST API
    # https://apility.io/apidocs/#get-the-as-information-from-an-ip-v2-0
    # Note: currently unused
    def queryAsIp(self, qry):
        headers = {
            'Accept': 'application/json',
            'X-Auth-Token': self.opts['api_key']
        }
        res = self.sf.fetchUrl('https://api.apility.net/v2.0/as/ip/' + qry,
                               headers=headers,
                               timeout=15,
                               useragent=self.opts['_useragent'])

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Parse API response
    def parseApiResponse(self, res):
        # https://apility.io/docs/step-4-plans-pricing/
        # https://apility.io/docs/difference-hits-requests/
        if res['code'] == "429":
            self.sf.error("You are being rate-limited by apility ")
            self.errorState = True
            return None

        if res['code'] == "404":
            return None

        if res['content'] is None:
            return None

        if res['content'] == 'Unauthorized':
            self.sf.error("Authentication failed")
            self.errorState = True
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.sf.debug(f"Error processing JSON response: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if eventData in self.results:
            return

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_apility but did not set an API key!")
            self.errorState = True
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName == 'IP_ADDRESS':
            data = self.queryBadIp(eventData)

            if data is None:
                self.sf.debug("No matches found for " + eventData)
                return

            res = data.get('response')

            if not res:
                self.sf.debug("No matches found for " + eventData)
                return

            for m in res:
                if m == 'FREEMAIL' and not self.opts['malicious_freemail']:
                    continue
                evt = SpiderFootEvent('MALICIOUS_IPADDR', m + ' [' + eventData + ']', self.__name__, event)
                self.notifyListeners(evt)

        if eventName == 'INTERNET_NAME':
            data = self.queryBadDomain(eventData)

            if data is None:
                self.sf.debug("No matches found for " + eventData)
                return

            res = data.get('response')

            if not res:
                self.sf.debug("No matches found for " + eventData)
                return

            evt = SpiderFootEvent('RAW_RIR_DATA', str(res), self.__name__, event)
            self.notifyListeners(evt)

            if res.get('ip'):
                ip_address = res.get('ip').get('address')
                if ip_address:
                    if self.sf.isValidLocalOrLoopbackIp(ip_address):
                        evt = SpiderFootEvent("INTERNAL_IP_ADDRESS", ip_address, self.__name__, event)
                        self.notifyListeners(evt)
                    elif self.sf.validIP(ip_address):
                        evt = SpiderFootEvent('IP_ADDRESS', ip_address, self.__name__, event)
                        self.notifyListeners(evt)
                    elif self.sf.validIP6(ip_address):
                        evt = SpiderFootEvent('IPV6_ADDRESS', ip_address, self.__name__, event)
                        self.notifyListeners(evt)

            domain = res.get('domain')

            if not domain:
                self.sf.debug("No matches found for " + eventData)
                return

            if domain.get('blacklist'):
                for m in domain.get('blacklist'):
                    if m == 'FREEMAIL' and not self.opts['malicious_freemail']:
                        continue
                    evt = SpiderFootEvent('MALICIOUS_INTERNET_NAME', m + ' [' + eventData + ']', self.__name__, event)
                    self.notifyListeners(evt)

            if domain.get('mx'):
                for mx in domain.get('mx'):
                    if mx == '.':
                        continue
                    evt = SpiderFootEvent('PROVIDER_MAIL', mx, self.__name__, event)
                    self.notifyListeners(evt)

            if domain.get('ns'):
                for ns in domain.get('ns'):
                    if ns == '.':
                        continue
                    evt = SpiderFootEvent('PROVIDER_DNS', ns, self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_apility class
