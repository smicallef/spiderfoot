#-------------------------------------------------------------------------------
# Name:         sfp_dns
# Purpose:      SpiderFoot plug-in for gathering IP addresses from sub-domains
#        and hostnames identified, and optionally affiliates.
#        Can also identify affiliates and other sub-domains based on
#        reverse-looking up the IP address identified.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     16/09/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
import socket
from sflib import SpiderFoot, SpiderFootPlugin

# SpiderFoot standard lib (must be initialized in __init__)
sf = None

results = dict()

class sfp_dns(SpiderFootPlugin):
    # Default options
    opts = {
        # These must always be set
        '_debug':           True,
        '_debugfilter':     '',
        'resolveaffiliate': True,   # Get IPs for affiliate domains
        'reverselookup':    True    # Reverse-resolve IPs to names for
                                    # more clues.
    }

    # URL this instance is working on
    seedUrl = None
    baseDomain = None # calculated from the URL in __init__

    def __init__(self, url, userOpts=dict()):
        global sf
        self.seedUrl = url

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # For error reporting, debug, etc.
        sf = SpiderFoot(self.opts)

        # Extract the 'meaningful' part of the FQDN from the URL
        self.baseDomain = sf.urlBaseDom(self.seedUrl)
        sf.debug('Base Domain: ' + self.baseDomain)

    # What events is this module interested in for input
    def watchedEvents(self):
        arr = ['SUBDOMAIN']
        if self.opts['resolveaffiliate']:
            arr.append('AFFILIATE')
        if self.opts['reverselookup']:
            arr.append('IP_ADDRESS')
        return arr

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventData):
        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if results.has_key(eventData):
            sf.debug("Skipping " + eventData + " as already resolved.")
            return None
        else:
            results[eventData] = True

        try:
            if eventName != 'IP_ADDRESS':
                addrs = socket.gethostbyname_ex(eventData)
            else:
                addrs = socket.gethostbyaddr(eventData)
        except socket.error as e:
            sf.debug("Unable to resolve " + eventData + ", (" + e.message + ")")
            return None
    
        # First element of tuple is primary hostname if requested name is 
        # a CNAME, or an IP is being reverse looked up
        if len(addrs[0]) > 0:
            host = addrs[0]
            sf.debug("Found possible URL: " + host)
            self.notifyListeners("URL", eventData, host)

        # If the returned hostname is on a different
        # domain to baseDomain, flag it as an affiliate
        if not host.endswith(self.baseDomain):
            self.notifyListeners("AFFILIATE", eventData, host)

        # In tests addr[1] was either always the requested lookup or empty

        # Now the IP addresses..
        if len(addrs[2]) > 0 and eventName != 'IP_ADDRESS':
            for ipaddr in addrs[2]:
                sf.debug("Found IP Address: " + ipaddr)
                self.notifyListeners("IP_ADDRESS", eventData, ipaddr)

        return None

# End of sfp_dns class

if __name__ == '__main__':
    print "This module cannot be run stand-alone."
    exit(-1)
