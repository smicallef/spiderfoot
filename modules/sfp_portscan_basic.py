#-------------------------------------------------------------------------------
# Name:         sfp_portscan_basic
# Purpose:      SpiderFoot plug-in for performing a basic port scan of IP
#               addresses identified.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/02/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
import socket
from sflib import SpiderFoot, SpiderFootPlugin

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_portscan_basic(SpiderFootPlugin):
    """Scans for commonly open TCP ports on Internet-facing systems."""

    # Default options
    opts = {
        # These must always be set
        '__debug':           True,
        '__debugfilter':     '',
                            # Commonly used ports on external-facing systems
        'ports':            [ 21, 22, 23, 25, 53, 79, 80, 81, 88, 110, 111, 
                            113, 119, 123, 137, 138, 139, 143, 161, 179,
                            389, 443, 445, 465, 512, 513, 514, 515, 631, 636,
                            990, 992, 993, 995, 1080, 8080, 8888, 9000 ],
        'timeout':          15
    }

    # Option descriptions
    optdescs = {
        'ports':    "The TCP ports to scan.",
        'timeout':  "Seconds before giving up on a port."
    }

    # URL this instance is working on
    seedUrl = None
    baseDomain = None # calculated from the URL in setup
    results = dict()

    def setup(self, url, userOpts=dict()):
        global sf
        self.seedUrl = url
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # For error reporting, debug, etc.
        sf = SpiderFoot(self.opts)

        # Extract the 'meaningful' part of the FQDN from the URL
        self.baseDomain = sf.urlBaseDom(self.seedUrl)
        sf.debug('Base Domain: ' + self.baseDomain)

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS']

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventData):
        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if self.results.has_key(eventData):
            sf.debug("Skipping " + eventData + " as already scanned.")
            return None
        else:
            self.results[eventData] = True

        for port in self.opts['ports']:
            if self.checkForStop():
                return None

            sf.debug("Checking port: " + str(port) + " against " + eventData)
            try:
                sock = socket.create_connection((eventData, port), self.opts['timeout'])
                sf.debug("TCP Port " + str(port) + " found to be OPEN.")
                self.notifyListeners("TCP_PORT_OPEN", eventData, str(port))
                sock.close()
            except Exception as e:
                sf.debug("Unable to connect to " + eventData + " on port " + str(port) + \
                    ": " + str(e))

        return None

# End of sfp_portscan_basic class

if __name__ == '__main__':
    print "This module cannot be run stand-alone."
    exit(-1)
