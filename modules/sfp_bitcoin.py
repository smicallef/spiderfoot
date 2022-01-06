# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_bitcoin
# Purpose:      SpiderFoot plug-in for scanning retrieved content by other
#               modules (such as sfp_spider) and identifying bitcoin numbers.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     27/05/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import codecs
import re
from hashlib import sha256

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_bitcoin(SpiderFootPlugin):

    meta = {
        'name': "Bitcoin Finder",
        'summary': "Identify bitcoin addresses in scraped webpages.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    opts = {}
    optdescs = {}

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT"]

    def producedEvents(self):
        return ["BITCOIN_ADDRESS"]

    def to_bytes(self, n, length):
        h = '%x' % n
        return codecs.decode(('0' * (len(h) % 2) + h).zfill(length * 2), "hex")

    def decode_base58(self, bc, length):
        digits58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        n = 0
        for char in bc:
            n = n * 58 + digits58.index(char)
        return self.to_bytes(n, length)

    def check_bc(self, bc):
        bcbytes = self.decode_base58(bc, 25)
        return bcbytes[-4:] == sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        sourceData = self.sf.hashstring(eventData)

        if sourceData in self.results:
            return

        self.results[sourceData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        addrs = list()

        # thanks to https://stackoverflow.com/questions/21683680/regex-to-match-bitcoin-addresses
        # Does not support keys or testnet addresses
        matches = re.findall(r"[\s:=\>](bc(0([ac-hj-np-z02-9]{39}|[ac-hj-np-z02-9]{59})|1[ac-hj-np-z02-9]{8,87})|[13][a-km-zA-HJ-NP-Z1-9]{25,35})", eventData)
        for m in matches:
            address = m[0]
            self.debug(f"Potential Bitcoin address match: {address}")

            if address.startswith('1') or address.startswith('3'):
                if self.check_bc(address):
                    addrs.append(address)
            else:
                addrs.append(address)

        for address in set(addrs):
            evt = SpiderFootEvent("BITCOIN_ADDRESS", address, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_bitcoin class
