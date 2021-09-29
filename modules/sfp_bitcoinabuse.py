# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_bitcoinabuse
# Purpose:      Check bitcoin address agains bitcoinabuse.com database
#
# Author:      Leo Trubach <leotrubach@gmail.com>
#
# Created:     2020-09-01
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from urllib.parse import urlencode

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
        self.results = self.tempStorage()

        if userOpts:
            self.opts.update(userOpts)

    def watchedEvents(self):
        return ["BITCOIN_ADDRESS"]

    def producedEvents(self):
        return ["MALICIOUS_BITCOIN_ADDRESS"]

    def query(self, address):
        params = {"address": address, "api_token": self.opts["api_key"]}
        qry = urlencode(params)
        res = self.sf.fetchUrl(
            f"https://www.bitcoinabuse.com/api/reports/check?{qry}",
            timeout=self.opts["_fetchtimeout"],
            useragent="SpiderFoot",
        )
        if res["code"] != "200":
            self.info(f"Failed to get results for {address}, code {res['code']}")
            return None

        if res["content"] is None:
            self.info(f"Failed to get results for {address}, empty content")
            return None

        try:
            return json.loads(res["content"])
        except Exception as e:
            self.error(f"Error processing JSON response from BitcoinAbuse: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error("You enabled sfp_bitcoinabuse but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "BITCOIN_ADDRESS":
            rec = self.query(eventData)
            if isinstance(rec, dict):
                count = rec.get("count")
                if isinstance(count, int):
                    if count > 0:
                        evt = SpiderFootEvent(
                            "MALICIOUS_BITCOIN_ADDRESS", f"BitcoinAbuse [{rec['address']}][https://www.bitcoinabuse.com/reports/{rec['address']}]", self.__name__, event
                        )
                        self.notifyListeners(evt)

                        rirevt = SpiderFootEvent(
                            "RAW_RIR_DATA", json.dumps(rec), self.__name__, event
                        )
                        self.notifyListeners(rirevt)
