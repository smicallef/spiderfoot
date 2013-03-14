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
from sflib import SpiderFoot, SpiderFootPlugin

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_ripe(SpiderFootPlugin):
    """Queries RIPE to identify netblocks and other info."""

    # Default options
    opts = { }

    # URL this instance is working on
    seedUrl = None
    baseDomain = None # calculated from the URL in setup
    results = dict()

    def setup(self, sfc, url, userOpts=dict()):
        global sf

        sf = sfc
        self.seedUrl = url
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # Extract the 'meaningful' part of the FQDN from the URL
        self.baseDomain = sf.urlBaseDom(self.seedUrl)

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'SUBDOMAIN']

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventData):
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
                sf.debug("No RIPE info found/available for " + eventData)
                return None

            # Just send the content off for others to process
            self.notifyListeners("WEBCONTENT", eventData, res['content'])
            return None

        # First get the netblock the IP resides on
        res = sf.fetchUrl("http://stat.ripe.net/data/network-info/data.json?resource=" + eventData)
        if res['content'] == None:
            sf.debug("No RIPE info found/available for " + eventData)
            return None

        j = json.loads(res['content'])
        prefix = j["data"]["prefix"]
        # Now see who owns the prefix
        res = sf.fetchUrl("http://stat.ripe.net/data/whois/data.json?resource=" + prefix)
        if res['content'] == None:
            sf.debug("No RIPE info found/available for prefix: " + prefix)
            return None

        # Crude..
        if self.baseDomain in res['content']:        
            self.notifyListeners("NETBLOCK", eventData, prefix)
            self.notifyListeners("WEBCONTENT", eventData, res['content'])

        return None

# End of sfp_ripe class

if __name__ == '__main__':
    print "This module cannot be run stand-alone."
    exit(-1)
