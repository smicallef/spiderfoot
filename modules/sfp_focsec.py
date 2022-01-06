# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_focsec
# Purpose:     Look up IP address information from Focsec.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-10-09
# Copyright:   (c) bcoles 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_focsec(SpiderFootPlugin):

    meta = {
        'name': "Focsec",
        'summary': "Look up IP address information from Focsec.",
        'flags': ['apikey'],
        'useCases': ["Passive", "Footprint", "Investigate"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://focsec.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.focsec.com/#ip",
            ],
            "apiKeyInstructions": [
                "Visit https://focsec.com/signup",
                "Register an account",
                "Visit https://focsec.com/account/dashboard and use the API key provided",
            ],
            'favIcon': "https://focsec.com/static/favicon.png",
            'logo': "https://focsec.com/static/web/images/logo.png",
            'description': "Our API lets you know if a user's IP address is associated with a VPN, Proxy, TOR or malicious bots."
            "Take your applications security to the next level by detecting suspicious activity early on."
        }
    }

    opts = {
        "api_key": "",
    }

    optdescs = {
        "api_key": "Focsec API Key.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.errorState = False
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS"
        ]

    def producedEvents(self):
        return [
            "RAW_RIR_DATA",
            "GEOINFO",
            "MALICIOUS_IPADDR",
            "PROXY_HOST",
            "VPN_HOST",
            "TOR_EXIT_NODE",
        ]

    def query(self, qry):
        """Retrieve IP address information from Focsec.

        Args:
            qry (str): IPv4/IPv6 address

        Returns:
            dict: JSON formatted results
        """

        params = urllib.parse.urlencode({
            'api_key': self.opts["api_key"],
        })

        res = self.sf.fetchUrl(
            f"https://api.focsec.com/v1/ip/{qry}?{params}",
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts['_useragent']
        )

        if not res:
            self.error("No response from Focsec.")
            return None

        if res['code'] == "400":
            self.error("Bad request.")
            self.errorState = True
            return None

        if res['code'] == "401":
            self.error("Unauthorized - Invalid API key.")
            self.errorState = True
            return None

        if res['code'] == "402":
            self.error("Unauthorized - Payment Required. Subscription or trial period expired.")
            self.errorState = True
            return None

        if res['code'] == "404":
            self.debug(f"No results for {qry}")
            return None

        # Future proofing - Focsec does not implement rate limiting
        if res['code'] == "429":
            self.error("You are being rate-limited by Focsec.")
            return None

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from Focsec.")
            return None

        if not res['content']:
            self.debug("No results from Focsec.")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        data = self.query(eventData)

        if not data:
            self.debug(f"Found no results for {eventData}")
            return

        e = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(e)

        is_bot = data.get('is_bot')
        if is_bot:
            e = SpiderFootEvent("MALICIOUS_IPADDR", f"Focsec [{eventData}]", self.__name__, event)
            self.notifyListeners(e)

        is_tor = data.get('is_tor')
        if is_tor:
            e = SpiderFootEvent("TOR_EXIT_NODE", eventData, self.__name__, event)
            self.notifyListeners(e)

        is_vpn = data.get('is_vpn')
        if is_vpn:
            e = SpiderFootEvent("VPN_HOST", eventData, self.__name__, event)
            self.notifyListeners(e)

        is_proxy = data.get('is_proxy')
        if is_proxy:
            e = SpiderFootEvent("PROXY_HOST", eventData, self.__name__, event)
            self.notifyListeners(e)

        location = ', '.join(
            filter(
                None,
                [
                    data.get('city'),
                    data.get('country'),
                ]
            )
        )

        if location:
            e = SpiderFootEvent("GEOINFO", location, self.__name__, event)
            self.notifyListeners(e)

# End of sfp_focsec class
