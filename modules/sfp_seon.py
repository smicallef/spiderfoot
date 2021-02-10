# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_seon
# Purpose:      Spiderfoot plugin to query seon.io to gather intelligence about 
#               IP Addresses, email addresses, and phone numbers
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     08/02/2021
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_seon(SpiderFootPlugin):

    meta = {
        'name': "https://seon.io/",
        'summary': "Queries seon.io to gather intelligence about IP Addresses, email addresses, and phone numbers",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Real World"],
        'dataSource': {
            'website': "https://seon.io/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://developers.seon.io/"
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
        'fraud_threshold': 10,
    }

    # Option descriptions
    optdescs = {
        'api_key': "API Key for seon.io",
        'fraud_threshold': 'Minimum fraud score for target to be marked as malicious(Seon.io considers anything 10+ as risky)',
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
            "SOCIAL_MEDIAL",
            "HUMAN_NAME",
            "COMPANY_NAME",
            "EMAILADDR_COMPROMISED",
            "MALICIOUS_PHONE_NUMBER",
            "PROVIDER_TELCO",
            "PHONE_NUMBER_TYPE"
            "RAW_RIR_DATA"
        ]

    def query(self, qry, eventName):
        if eventName == "IP_ADDRESS" or eventName = "IPV6_ADDRESS":
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

        if res['code'] != 200:
            return None

        return res['content']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_seon but did not set an API key!")
            self.errorState = True
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return None
        else:
            self.results[eventData] = True

        if eventName == "IP_ADDRESS" or eventName = "IPV6_ADDRESS":
            data = self.query(eventData, eventName)
            if data is None:
                return None
        elif eventName == "EMAILADDR":
            data = self.query(eventData, eventName)
            if data is None:
                return None
        elif eventName == "PHONE_NUMBER":
            data = self.query(eventData, eventName)
            if data is None:
                return None
        
        



# End of sfp_seon class
