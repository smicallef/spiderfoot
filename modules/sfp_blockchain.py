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
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_blockchain(SpiderFootPlugin):
    """Blockchain:Footprint,Investigate,Passive:Public Registries::Queries blockchain.info to find the balance of identified bitcoin wallet addresses."""


    # Default options
    opts = {}
    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
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

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        # Wallet balance
        res = self.sf.fetchUrl("https://blockchain.info/balance?active=" + eventData,
                               timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
        if res['content'] is None:
            self.sf.info("No Blockchain info found for " + eventData)
            return None
        try:
            data = json.loads(res['content'])
            balance = float(data[eventData]['final_balance']) / 100000000
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        evt = SpiderFootEvent("BITCOIN_BALANCE", str(balance) + " BTC", self.__name__, event)
        self.notifyListeners(evt)

        return None

# End of sfp_blockchain class
