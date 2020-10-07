# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ipqualityscore
# Purpose:      Spiderfoot module to check whether a target is malicious
#               using IPQualityScore API
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     2020-10-07
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------
import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_ipqualityscore(SpiderFootPlugin):

    meta = {
        "name": "IPQualityScore",
        "summary": "Determine if target is malicious using IPQualityScore API",
        "flags": ["apikey"],
        "useCases": ["Passive"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://www.ipqualityscore.com/",
            "model": "FREE_AUTH_LIMITED",
            "references": [
                "https://www.ipqualityscore.com/documentation/overview"
            ],
            "apiKeyInstructions": [
                "Visit https://www.ipqualityscore.com/",
                "Click on 'Plans'",
                "Register a free account",
                "Visit https://www.ipqualityscore.com/user/settings",
                "Your API key will be listed under 'API Key'"
            ],
            "favIcon": "https://www.ipqualityscore.com/templates/img/icons/fav/favicon-32x32.png",
            "logo": "https://www.ipqualityscore.com/templates/img/logo.png",
            "description": "IPQualityScore's suite of fraud prevention tools automate quality control "
            "to prevent bots, fake accounts, fraudsters, suspicious transactions, "
            "& malicious users without interrupting the user experience.",
        },
    }

    opts = {
        "api_key": "",
    }

    optdescs = {
        "api_key": "IPQualityScore API Key",
    }

    errorState = False

    def setup(self, sfc, userOpts=None):
        if userOpts is None:
            userOpts = {}
        self.sf = sfc
        self.results = self.tempStorage()
        self.opts.update(userOpts)

    def watchedEvents(self):
        return [
            "PHONE_NUMBER",
            "EMAILADDR",
            "IP_ADDRESS",
            "DOMAIN_NAME"
        ]

    def producedEvents(self):
        return [
            "MALICIOUS_PHONE_NUMBER",
            "MALICIOUS_EMAILADDR",
            "MALICIOUS_IPADDR",
            "MALICIOUS_INTERNET_NAME",
            "RAW_RIR_DATA"
        ]

    def handle_error_response(self, qry, res):
        try:
            error_info = json.loads(res["content"])
        except Exception:
            error_info = None
        if error_info:
            error_message = error_info.get("message")
        else:
            error_message = None
        if error_message:
            error_str = f", message {error_message}"
        else:
            error_str = ""
        self.sf.error(f"Failed to get results for {qry}, code {res['code']}{error_str}")

    def query(self, qry, eventName):
        queryString = ""
        if eventName == "PHONE_NUMBER":
            queryString = f"https://ipqualityscore.com/api/json/phone/{self.opts['api_key']}/{qry}"
        elif eventName == "EMAILADDR":
            queryString = f"https://ipqualityscore.com/api/json/email/{self.opts['api_key']}/{qry}"
        elif eventName == "IP_ADDRESS" or eventName == "DOMAIN_NAME":
            queryString = f"https://ipqualityscore.com/api/json/ip/{self.opts['api_key']}/{qry}"

        res = self.sf.fetchUrl(
            queryString,
            timeout=self.opts["_fetchtimeout"],
            useragent="SpiderFoot",
        )

        success = json.loads(res["content"]).get("success")
        if res["code"] != "200" or not success:
            self.handle_error_response(qry, res)
            return None

        if res['content'] is None:
            self.sf.info(f"No IPQualityScore info found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.sf.error(f"Error processing JSON response from IPQualityScore: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.sf.error(
                f"You enabled {self.__class__.__name__} but did not set an API Key!"
            )
            self.errorState = True
            return None

        self.results[eventData] = True

        data = self.query(eventData, eventName)

        if data is None:
            return

        fraudScore = data.get('fraud_score')
        recentAbuse = data.get('recent_abuse')
        botStatus = data.get('bot_status')
        if fraudScore >= 85 or recentAbuse or botStatus:
            evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
            self.notifyListeners(evt)

            if eventName == "PHONE_NUMBER":
                evt = SpiderFootEvent("MALICIOUS_PHONE_NUMBER", eventData, self.__name__, event)
                self.notifyListeners(evt)
            elif eventName == "EMAILADDR":
                evt = SpiderFootEvent("MALICIOUS_EMAILADDR", eventData, self.__name__, event)
                self.notifyListeners(evt)
            elif eventName == "IP_ADDRESS":
                evt = SpiderFootEvent("MALICIOUS_IPADDR", eventData, self.__name__, event)
                self.notifyListeners(evt)
            elif eventName == "DOMAIN_NAME":
                evt = SpiderFootEvent("MALICIOUS_INTERNET_NAME", eventData, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_ipqualityscore class
