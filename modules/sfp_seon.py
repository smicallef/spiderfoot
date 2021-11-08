# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_seon
# Purpose:      Spiderfoot plugin to query seon.io to gather intelligence about
#               IP Addresses, email addresses, and phone numbers.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     08/02/2021
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_seon(SpiderFootPlugin):

    meta = {
        'name': "Seon",
        'summary': "Queries seon.io to gather intelligence about IP Addresses, email addresses, and phone numbers",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://seon.io/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://docs.seon.io/api-reference",
            ],
            'apiKeyInstructions': [
                "Visit https://seon.io/",
                "Register an account",
                "Visit https://docs.seon.io/api-reference",
                "Your API key is listed under 'License key'",
            ],
            'favIcon': "https://seon.io/assets/favicons/favicon-16x16.png",
            'logo': "https://seon.io/assets/favicons/apple-touch-icon-152.png",
            'description': "SEON Fraud Prevention tools help organisations reduce "
            "the costs and resources lost to fraud. Spot fake accounts, slash manual reviews and cut chargebacks now.",
        }
    }

    # Default options
    opts = {
        'api_key': '',
        'fraud_threshold': 80,
    }

    # Option descriptions
    optdescs = {
        'api_key': "seon.io API Key",
        'fraud_threshold': 'Minimum fraud score for target to be marked as malicious (0-100)',
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
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "EMAILADDR",
            "PHONE_NUMBER"
        ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [
            "GEOINFO",
            "MALICIOUS_IPADDR",
            "TCP_PORT_OPEN",
            "MALICIOUS_EMAILADDR",
            "EMAILADDR_DELIVERABLE",
            "EMAILADDR_UNDELIVERABLE",
            "SOCIAL_MEDIA",
            "HUMAN_NAME",
            "COMPANY_NAME",
            "EMAILADDR_COMPROMISED",
            "MALICIOUS_PHONE_NUMBER",
            "PROVIDER_TELCO",
            "PHONE_NUMBER_TYPE",
            "WEBSERVER_TECHNOLOGY",
            "RAW_RIR_DATA",
            "TOR_EXIT_NODE",
            "VPN_HOST",
            "PROXY_HOST",
        ]

    def query(self, qry, eventName):
        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            queryString = f"https://api.seon.io/SeonRestService/ip-api/v1.0/{qry}"
        elif eventName == "EMAILADDR":
            queryString = f"https://api.seon.io/SeonRestService/email-api/v2.0/{qry}"
        elif eventName == "PHONE_NUMBER":
            queryString = f"https://api.seon.io/SeonRestService/phone-api/v1.0/{qry}"

        headers = {
            'Accept': "application/json",
            'X-API-KEY': self.opts['api_key']
        }

        res = self.sf.fetchUrl(
            queryString,
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        if res['code'] == '429':
            self.error("You are being rate-limited by seon.io")
            return None

        if res['code'] != "200":
            self.error("Error retrieving search results from seon.io")
            return None

        if res['code'] == '404':
            self.error("API Endpoint not found")
            return None

        return json.loads(res['content'])

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_seon but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        dataFound = False
        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            data = self.query(eventData, eventName)
            if data is None:
                return

            resultSet = data.get('data')
            if resultSet:
                if resultSet.get('score', 0) >= self.opts['fraud_threshold']:
                    maliciousDesc = f"SEON [{eventData}]\n - FRAUD SCORE: {resultSet.get('score')}"
                    evt = SpiderFootEvent("MALICIOUS_IPADDR", maliciousDesc, self.__name__, event)
                    self.notifyListeners(evt)
                    dataFound = True

                    if resultSet.get('tor'):
                        evt = SpiderFootEvent("WEBSERVER_TECHNOLOGY", f"Server is TOR node: {resultSet.get('tor')}", self.__name__, event)
                        self.notifyListeners(evt)

                        evt = SpiderFootEvent("TOR_EXIT_NODE", eventData, self.__name__, event)
                        self.notifyListeners(evt)

                    if resultSet.get('vpn'):
                        evt = SpiderFootEvent("WEBSERVER_TECHNOLOGY", f"Server is VPN: {resultSet.get('vpn')}", self.__name__, event)
                        self.notifyListeners(evt)

                        evt = SpiderFootEvent("VPN_HOST", eventData, self.__name__, event)
                        self.notifyListeners(evt)

                    if resultSet.get('web_proxy'):
                        evt = SpiderFootEvent("WEBSERVER_TECHNOLOGY", f"Server is Web Proxy: {resultSet.get('web_proxy')}", self.__name__, event)
                        self.notifyListeners(evt)

                        evt = SpiderFootEvent("PROXY_HOST", eventData, self.__name__, event)
                        self.notifyListeners(evt)

                    if resultSet.get('public_proxy'):
                        evt = SpiderFootEvent("WEBSERVER_TECHNOLOGY", f"Server is Public Proxy: {resultSet.get('public_proxy')}", self.__name__, event)
                        self.notifyListeners(evt)

                        evt = SpiderFootEvent("PROXY_HOST", eventData, self.__name__, event)
                        self.notifyListeners(evt)

                if resultSet.get('country'):
                    location = ', '.join(filter(None, [resultSet.get('city'), resultSet.get('state_prov'), resultSet.get('country')]))
                    evt = SpiderFootEvent('GEOINFO', location, self.__name__, event)
                    self.notifyListeners(evt)

                    evt = SpiderFootEvent('PHYSICAL_COORDINATES', f"{resultSet.get('latitude')}, {resultSet.get('longitude')}", self.__name__, event)
                    self.notifyListeners(evt)
                    dataFound = True

                if resultSet.get('open_ports'):
                    for port in resultSet.get('open_ports'):
                        evt = SpiderFootEvent('TCP_PORT_OPEN', f"{eventData}:{port}", self.__name__, event)
                        self.notifyListeners(evt)
                        dataFound = True

                if dataFound:
                    evt = SpiderFootEvent('RAW_RIR_DATA', str(resultSet), self.__name__, event)
                    self.notifyListeners(evt)

        elif eventName == "EMAILADDR":
            data = self.query(eventData, eventName)
            if data is None:
                return

            resultSet = data.get('data')
            if resultSet:
                if resultSet.get('score') >= self.opts['fraud_threshold']:
                    maliciousDesc = f"SEON [{eventData}]\n - FRAUD SCORE: {resultSet.get('score')}"
                    evt = SpiderFootEvent("MALICIOUS_EMAILADDR", maliciousDesc, self.__name__, event)
                    self.notifyListeners(evt)
                    dataFound = True

                if resultSet.get('deliverable'):
                    evt = SpiderFootEvent("EMAILADDR_DELIVERABLE", eventData, self.__name__, event)
                    self.notifyListeners(evt)
                    dataFound = True
                else:
                    evt = SpiderFootEvent("EMAILADDR_UNDELIVERABLE", eventData, self.__name__, event)
                    self.notifyListeners(evt)
                    dataFound = True

                if resultSet.get('domain_details'):
                    if resultSet.get('domain_details').get('disposable'):
                        evt = SpiderFootEvent("EMAILADDR_DISPOSABLE", eventData, self.__name__, event)
                        self.notifyListeners(evt)
                        dataFound = True

                if resultSet.get('account_details'):
                    socialMediaList = resultSet.get('account_details').keys()
                    for site in socialMediaList:
                        if resultSet.get('account_details').get(site):
                            if resultSet.get('account_details').get(site).get('url'):
                                evt = SpiderFootEvent("SOCIAL_MEDIA", f"{site}: <SFURL>{resultSet.get('account_details').get(site).get('url')}</SFURL>", self.__name__, event)
                                self.notifyListeners(evt)
                            elif resultSet.get('account_details').get(site).get('registered'):
                                evt = SpiderFootEvent("SOCIAL_MEDIA", f"Registered on {site}", self.__name__, event)
                                self.notifyListeners(evt)
                            dataFound = True

                            if site == 'linkedin':
                                if resultSet.get('account_details').get(site).get('company'):
                                    evt = SpiderFootEvent("COMPANY_NAME", resultSet.get('account_details').get(site).get('company'), self.__name__, event)
                                    self.notifyListeners(evt)
                                    dataFound = True

                                if resultSet.get('account_details').get(site).get('name'):
                                    evt = SpiderFootEvent("HUMAN_NAME", resultSet.get('account_details').get(site).get('name'), self.__name__, event)
                                    self.notifyListeners(evt)
                                    dataFound = True

                if resultSet.get('breach_details').get('breaches'):
                    breachList = resultSet.get('breach_details').get('breaches')
                    for breachSet in breachList:
                        evt = SpiderFootEvent("EMAILADDR_COMPROMISED", f"{eventData} [{breachSet.get('name', 'Unknown')}]", self.__name__, event)
                        self.notifyListeners(evt)
                        dataFound = True

                if dataFound:
                    evt = SpiderFootEvent('RAW_RIR_DATA', str(resultSet), self.__name__, event)
                    self.notifyListeners(evt)

        elif eventName == "PHONE_NUMBER":
            data = self.query(eventData, eventName)
            if data is None:
                return

            resultSet = data.get('data')
            if resultSet:
                if resultSet.get('score') >= self.opts['fraud_threshold']:
                    maliciousDesc = f"SEON [{eventData}]\n - FRAUD SCORE: {resultSet.get('score')}"
                    evt = SpiderFootEvent("MALICIOUS_PHONE_NUMBER", maliciousDesc, self.__name__, event)
                    self.notifyListeners(evt)
                    dataFound = True

                if resultSet.get('account_details'):
                    socialMediaList = resultSet.get('account_details').keys()
                    for site in socialMediaList:
                        if resultSet.get('account_details').get(site).get('registered'):
                            evt = SpiderFootEvent("SOCIAL_MEDIA", f"Registered on {site}", self.__name__, event)
                            self.notifyListeners(evt)
                            dataFound = True

                if resultSet.get('type'):
                    evt = SpiderFootEvent("PHONE_NUMBER_TYPE", resultSet.get('type'), self.__name__, event)
                    self.notifyListeners(evt)
                    dataFound = True

                if resultSet.get('carrier'):
                    evt = SpiderFootEvent("PROVIDER_TELCO", resultSet.get('carrier'), self.__name__, event)
                    self.notifyListeners(evt)
                    dataFound = True

                if dataFound:
                    evt = SpiderFootEvent('RAW_RIR_DATA', str(resultSet), self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_seon class
