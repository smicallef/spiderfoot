# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_bitcoinabuse
# Purpose:      Check bitcoin address agains bitcoinabuse.com database
#
# Author:      Leo Trubach <leotrubach@gmail.com>
#
# Created:     2020-09-01
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_bitcoinabuse(SpiderFootPlugin):
    meta = {
        "name": "BitcoinAbuse",
        "summary": "Check Bitcoin addresses against the bitcoinabuse.com database of suspect/malicious addresses.",
        'flags': ["apikey"],
        "useCases": ["Passive", "Investigate"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://www.bitcoinabuse.com/",
            "model": "FREE_AUTH_UNLIMITED",
            "references": ["https://www.bitcoinabuse.com/api-docs"],
            "apiKeyInstructions": [
                "Visit https://www.bitcoinabuse.com/register",
                "Register a free account",
                "Click on the account icon and click on 'Your Settings'",
                "Click on 'API'",
                "Enter a token name and press 'Create'",
            ],
            "favIcon": "https://www.bitcoinabuse.com/favicon-32x32.png",
            "logo": "https://www.bitcoinabuse.com/img/logo-sm.png",
            "description": "BitcoinAbuse.com is a public database of bitcoin "
            "addresses used by scammers, hackers, and criminals."
            "Bitcoin is anonymous if used perfectly. Luckily, no "
            "one is perfect. Even hackers make mistakes. It only "
            "takes one slip to link stolen bitcoin to a hacker's "
            "their real identity. It is our hope that by making a "
            "public database of bitcoin addresses used by criminals it "
            "will be harder for criminals to convert the digital currency"
            " back into fiat money.",
        },
    }
    opts = {
        "api_key": "",
    }
    optdescs = {
        "api_key": "BitcoinAbuse API Key.",
    }
    results = None
    errorState = False

    def setup(self, sfc, userOpts=None):
        self.sf = sfc
        self.errorState = False
        self.results = self.tempStorage()

        if userOpts:
            self.opts.update(userOpts)

    def watchedEvents(self):
        return ["BITCOIN_ADDRESS"]

    def producedEvents(self):
        return [
            "MALICIOUS_BITCOIN_ADDRESS",
            "RAW_RIR_DATA",
        ]

    def queryAddress(self, address: str):
        params = {
            "address": address,
            "api_token": self.opts["api_key"]
        }

        res = self.sf.fetchUrl(
            f"https://www.bitcoinabuse.com/api/reports/check?{urllib.parse.urlencode(params)}",
            timeout=self.opts["_fetchtimeout"],
            useragent="SpiderFoot",
        )

        # All endpoints other than Report Address have a rate limit of
        # 30 requests per minute or one request every two seconds on average.
        time.sleep(2)

        return self.parseApiResponse(res)

    def parseApiResponse(self, res: dict):
        if not res:
            self.error("No response from BitcoinAbuse.")
            return None

        if res['code'] == '404':
            self.debug("No results for query")
            return None

        if res['code'] == "401":
            self.error("Invalid BitcoinAbuse API key.")
            self.errorState = True
            return None

        if res['code'] == '429':
            self.error("You are being rate-limited by BitcoinAbuse")
            self.errorState = True
            return None

        if res['code'] in ['500', '502', '503']:
            self.error("BitcoinAbuse service unavailable")
            self.errorState = True
            return None

        # Catch all other non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error("Failed to retrieve content from BitcoinAbuse")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response from BitcoinAbuse: {e}")

        return None

    def handleEvent(self, event):
        if self.errorState:
            return

        eventName = event.eventType

        self.debug(f"Received event, {eventName}, from {event.module}")

        if self.opts["api_key"] == "":
            self.error(f"You enabled {self.__class__.__name__} but did not set an API key!")
            self.errorState = True
            return

        eventData = event.data

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "BITCOIN_ADDRESS":
            rec = self.queryAddress(eventData)

            if not rec:
                return

            if not isinstance(rec, dict):
                return

            count = rec.get("count")

            if not count:
                return

            if not isinstance(count, int):
                return

            address = rec.get('address')

            if not address:
                return

            url = f"https://www.bitcoinabuse.com/reports/{address}"
            evt = SpiderFootEvent(
                "MALICIOUS_BITCOIN_ADDRESS",
                f"BitcoinAbuse [{address}]\n<SFURL>{url}</SFURL>",
                self.__name__,
                event
            )
            self.notifyListeners(evt)

            rirevt = SpiderFootEvent(
                "RAW_RIR_DATA", json.dumps(rec), self.__name__, event
            )
            self.notifyListeners(rirevt)
