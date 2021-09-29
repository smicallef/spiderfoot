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
        'flags': ["apikey"],
        "useCases": ["Investigate", "Passive"],
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
        "abuse_score_threshold": 85,
        "strictness": 0
    }

    optdescs = {
        "api_key": "IPQualityScore API Key",
        "abuse_score_threshold": "Minimum abuse score for target to be considered malicious (0 - 100)",
        "strictness": "Depth of the reputation checks to be performed on the target (0 - 2)"
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
            "DOMAIN_NAME",
            "EMAILADDR",
            "IP_ADDRESS",
            "PHONE_NUMBER",
        ]

    def producedEvents(self):
        return [
            "EMAILADDR_DISPOSABLE",
            "EMAILADDR_COMPROMISED",
            "GEOINFO",
            "MALICIOUS_PHONE_NUMBER",
            "MALICIOUS_EMAILADDR",
            "MALICIOUS_IPADDR",
            "MALICIOUS_INTERNET_NAME",
            "PHONE_NUMBER_TYPE",
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
        self.error(f"Failed to get results for {qry}, code {res['code']}{error_str}")

    def query(self, qry, eventName):
        queryString = ""
        if eventName == "PHONE_NUMBER":
            queryString = f"https://ipqualityscore.com/api/json/phone/{self.opts['api_key']}/{qry}?strictness={self.opts['strictness']}"
        elif eventName == "EMAILADDR":
            queryString = f"https://ipqualityscore.com/api/json/email/{self.opts['api_key']}/{qry}?strictness={self.opts['strictness']}"
        elif eventName in ['IP_ADDRESS', 'DOMAIN_NAME']:
            queryString = f"https://ipqualityscore.com/api/json/ip/{self.opts['api_key']}/{qry}?strictness={self.opts['strictness']}"

        res = self.sf.fetchUrl(
            queryString,
            timeout=self.opts["_fetchtimeout"],
            useragent="SpiderFoot",
        )

        if not res['content']:
            self.info(f"No IPQualityScore info found for {qry}")
            return None

        try:
            r = json.loads(res['content'])
            if res["code"] != "200" or not r.get("success"):
                self.handle_error_response(qry, res)
                return None
            return r
        except Exception as e:
            self.error(f"Error processing JSON response from IPQualityScore: {e}")

        return None

    def getGeoInfo(self, data):
        geoInfo = ""

        city = data.get('city')
        country = data.get('country')
        if not country:
            country = data.get('country_code')
        zipcode = data.get('zip_code')
        region = data.get('region')

        if city:
            geoInfo += city + ", "
        if region:
            geoInfo += region + ", "
        if country:
            geoInfo += country + " "
        if zipcode:
            geoInfo += zipcode

        return geoInfo

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API Key!"
            )
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already mapped.")
            return
        self.results[eventData] = True

        data = self.query(eventData, eventName)
        if not data:
            return

        fraudScore = data.get('fraud_score')
        recentAbuse = data.get('recent_abuse')
        botStatus = data.get('bot_status')
        malicious = False
        maliciousDesc = ""

        if fraudScore >= self.opts['abuse_score_threshold'] or recentAbuse or botStatus:
            evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
            self.notifyListeners(evt)
            malicious = True
            maliciousDesc = f"IPQualityScore [{eventData}]\n"

        if eventName == "PHONE_NUMBER":
            if malicious:
                maliciousDesc += f" - FRAUD SCORE: {fraudScore}\n - ACTIVE: {data.get('active')}\n - RISKY: {data.get('risky')}\n - RECENT ABUSE: {recentAbuse}"
                evt = SpiderFootEvent("MALICIOUS_PHONE_NUMBER", maliciousDesc, self.__name__, event)
                self.notifyListeners(evt)

            phoneNumberType = data.get('line_type')
            if phoneNumberType:
                evt = SpiderFootEvent("PHONE_NUMBER_TYPE", phoneNumberType, self.__name__, event)
                self.notifyListeners(evt)

            geoInfo = self.getGeoInfo(data)
            if geoInfo:
                evt = SpiderFootEvent("GEOINFO", geoInfo, self.__name__, event)
                self.notifyListeners(evt)

        elif eventName == "EMAILADDR":
            if malicious:
                maliciousDesc += f" - FRAUD SCORE: {fraudScore}\n - HONEYPOT: {data.get('honeypot')}\n - SPAM TRAP SCORE: {data.get('spam_trap_score')}\n - RECENT ABUSE: {recentAbuse}"
                evt = SpiderFootEvent("MALICIOUS_EMAILADDR", maliciousDesc, self.__name__, event)
                self.notifyListeners(evt)

            if data.get('disposable'):
                evt = SpiderFootEvent("EMAILADDR_DISPOSABLE", eventData, self.__name__, event)
                self.notifyListeners(evt)

            if data.get('leaked'):
                evt = SpiderFootEvent("EMAILADDR_COMPROMISED", f"{eventData} [Unknown]", self.__name__, event)
                self.notifyListeners(evt)

        elif eventName in ['IP_ADDRESS', 'DOMAIN_NAME']:
            if malicious:
                maliciousDesc += f" - FRAUD SCORE: {fraudScore}\n - BOT STATUS: {botStatus}\n - RECENT ABUSE: {recentAbuse}\n - ABUSE VELOCITY: {data.get('abuse_velocity')}\n - VPN: {data.get('vpn')}\n - ACTIVE VPN: {data.get('active_vpn')}\n - TOR: {data.get('tor')}\n - ACTIVE TOR: {data.get('active_tor')}"

                if eventName == "IP_ADDRESS":
                    evt = SpiderFootEvent("MALICIOUS_IPADDR", maliciousDesc, self.__name__, event)
                elif eventName == "DOMAIN_NAME":
                    evt = SpiderFootEvent("MALICIOUS_INTERNET_NAME", maliciousDesc, self.__name__, event)
                self.notifyListeners(evt)

            geoInfo = self.getGeoInfo(data)
            if geoInfo:
                evt = SpiderFootEvent("GEOINFO", geoInfo, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_ipqualityscore class
