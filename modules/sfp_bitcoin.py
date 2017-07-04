# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_bitcoin
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) and identifying bitcoin numbers.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     27/05/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

try:
    import re2 as re
except ImportError:
    import re
from hashlib import sha256
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_bitcoin(SpiderFootPlugin):
    """Bitcoin Finder:Footprint,Investigate:Content Analysis::Identify bitcoin addresses in scraped webpages."""


    # Default options
    opts = {}

    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["BITCOIN_ADDRESS"]

    def to_bytes(self, n, length):
        h = '%x' % n
        s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
        return s
      
    def decode_base58(self, bc, length):
        digits58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        n = 0
        for char in bc:
            n = n * 58 + digits58.index(char)
        return self.to_bytes(n, length)

    def check_bc(self, bc):
        bcbytes = self.decode_base58(bc, 25)
        return bcbytes[-4:] == sha256(sha256(bcbytes[:-4]).digest()).digest()[:4]
 
    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        sourceData = self.sf.hashstring(eventData)

        if sourceData in self.results:
            return None
        else:
            self.results.append(sourceData)

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # thanks to https://stackoverflow.com/questions/21683680/regex-to-match-bitcoin-addresses
        matches = re.findall("[\s:=\>]([13][a-km-zA-HJ-NP-Z1-9]{25,34})", eventData)
        for m in matches:
            self.sf.debug("Bitcoin potential match: " + m)
            if self.check_bc(m):
                evt = SpiderFootEvent("BITCOIN_ADDRESS", m, self.__name__, event)
                self.notifyListeners(evt)

        return None

# End of sfp_bitcoin class
