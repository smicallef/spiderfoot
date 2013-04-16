#-------------------------------------------------------------------------------
# Name:         sfp_ripe
# Purpose:      Some RIPE (http://stat.ripe.net) queries to get netblocks owned
#               and other bits of info.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     11/03/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
import json
import socket
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_ripe(SpiderFootPlugin):
    """Queries RIPE to identify netblocks and other info."""

    # Default options
    opts = { }

    # Target
    baseDomain = None
    results = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'SUBDOMAIN']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if self.results.has_key(eventData):
            sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if eventName == 'SUBDOMAIN':
            res = sf.fetchUrl("http://stat.ripe.net/data/dns-chain/data.json?resource=" + eventData)
            if res['content'] == None:
                sf.info("No RIPE info found/available for " + eventData)
                return None

            j = json.loads(res['content'])
            nslist = j["data"]["authoritative_nameservers"]
            for ns in nslist:
                nsclean = ns.rstrip('.')
                if not nsclean.endswith(self.baseDomain):
                    evt = SpiderFootEvent("AFFILIATE", nsclean, self.__name__, event)
                    self.notifyListeners(evt)

            # Just send the content off for others to process
            evt = SpiderFootEvent("RAW_DATA", res['content'], self.__name__, event)
            self.notifyListeners(evt)
            return None

        # First get the netblock the IP resides on
        res = sf.fetchUrl("http://stat.ripe.net/data/network-info/data.json?resource=" + eventData)
        if res['content'] == None:
            sf.info("No RIPE info found/available for " + eventData)
            return None

        j = json.loads(res['content'])
        prefix = j["data"]["prefix"]
        # Now see who owns the prefix
        res = sf.fetchUrl("http://stat.ripe.net/data/whois/data.json?resource=" + prefix)
        if res['content'] == None:
            sf.info("No RIPE info found/available for prefix: " + prefix)
            return None

        # Crude and probably prone to a lot of false positives. Need to revisit.
        if self.baseDomain in res['content']:        
            sf.info("Owned netblock found: " + prefix)
            evt = SpiderFootEvent("NETBLOCK", prefix, self.__name__, event)
            self.notifyListeners(evt)
            evt = SpiderFootEvent("RAW_DATA", res['content'], self.__name__, event)
            self.notifyListeners(evt)

        return None

    def start(self):
        res = sf.fetchUrl("http://stat.ripe.net/data/dns-chain/data.json?resource=" + \
            self.baseDomain)
        if res['content'] == None:
            sf.info("No RIPE info found/available for " + self.baseDomain)
            return None

        j = json.loads(res['content'])
        nslist = j["data"]["authoritative_nameservers"]
        for ns in nslist:
            nsclean = ns.rstrip('.')
            if not nsclean.endswith(self.baseDomain):
                evt = SpiderFootEvent("AFFILIATE", nsclean, self.__name__)
                self.notifyListeners(evt)

        # Just send the content off for others to process
        evt = SpiderFootEvent("RAW_DATA", res['content'], self.__name__)
        self.notifyListeners(evt)
        return None
       
# End of sfp_ripe class
