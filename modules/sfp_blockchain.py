# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_blockchain
# Purpose:      SpiderFoot plug-in to look up a bitcoin wallet's balance by
#               querying blockchain.info.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     18/06/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_blockchain(SpiderFootPlugin):

    meta = {
        'name': "Blockchain",
        'summary': "Queries blockchain.info to find the balance of identified bitcoin wallet addresses.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Public Registries"],
        'dataSource': {
            'website': "https://www.blockchain.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://exchange.blockchain.com/api/#introduction",
                "https://exchange.blockchain.com/markets",
                "https://exchange.blockchain.com/fees",
                "https://exchange.blockchain.com/trade"
            ],
            'favIcon': "https://www.blockchain.com/static/favicon.ico",
            'logo': "https://exchange.blockchain.com/api/assets/images/logo.png",
            'description': "Blockchain Exchange is the most secure place to buy, sell, and trade crypto.\n"
            "Use the most popular block explorer to search and "
            "verify transactions on the Bitcoin, Ethereum, and Bitcoin Cash blockchains.\n"
            "Stay on top of Bitcoin and other top cryptocurrency prices, news, and market information.",
        }
    }

    # Default options
    opts = {}
    optdescs = {}

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['BITCOIN_ADDRESS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["BITCOIN_BALANCE"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Wallet balance
        res = self.sf.fetchUrl("https://blockchain.info/balance?active=" + eventData,
                               timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
        if res['content'] is None:
            self.info("No Blockchain info found for " + eventData)
            return
        try:
            data = json.loads(res['content'])
            balance = float(data[eventData]['final_balance']) / 100000000
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return

        evt = SpiderFootEvent("BITCOIN_BALANCE", str(balance) + " BTC", self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_blockchain class
