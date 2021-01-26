# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_etherscan
# Purpose:      SpiderFoot plug-in to look up a bitcoin wallet's balance by
#               querying etherscan.io.
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     26/01/2021
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_etherscan(SpiderFootPlugin):

    meta = {
        'name': "Etherscan",
        'summary': "Queries etherscan.io to find the balance of identified bitcoin wallet addresses.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://etherscan.io",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://etherscan.io/apis"
            ],
            'apiKeyInstructions': [
                "Visit https://etherscan.io",
                "Register a free account",
                "Browse to https://etherscan.io/myapikey",
                "Click on Add beside API Key",
                "Your API Key will be listed under API Key Token",
            ],
            'favIcon': "https://etherscan.io/images/favicon3.ico",
            'logo': "https://etherscan.io/images/brandassets/etherscan-logo-circle.png",
            'description': "Etherscan allows you to explore and search the Ethereum blockchain "
            "for transactions, addresses, tokens, prices and other activities taking place on Ethereum (ETH)",
        }
    }

    # Default options
    opts = {
        'api_key': '',
    }

    # Option descriptions
    optdescs = {
        'api_key': "API Key for etherscan.io",
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
            "ETHEREUM_ADDRESS"
            ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [
            "ETHEREUM_ADDRESS",
            "RAW_RIR_DATA"
        ]


    def query(self, qry):
        queryString = f"https://api.etherscan.io/api?module=account&action=balance&address={qry}&tag=latest&apikey={self.opts['api_key']}"
        # Wallet balance
        res = self.sf.fetchUrl(queryString,
                               timeout=self.opts['_fetchtimeout'], 
                               useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.info(f"No Etherscan data found for {qry}")
            return None
        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug(f"Error processing JSON response: {e}")
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return None
        else:
            self.results[eventData] = True

        data = query(eventData)
        balance = float(data.get('result')) / 100000000

        evt = SpiderFootEvent("ETHEREUM_ADDRESS", f"{str(balance)} ETH", self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_etherscan class
