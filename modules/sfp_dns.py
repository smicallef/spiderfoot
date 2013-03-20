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

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_dns(SpiderFootPlugin):
    """Performs a number of DNS checks to obtain IP Addresses and Affiliates."""

    # Default options
    opts = {
        'resolveaffiliate': False,   # Get IPs for affiliate domains
        'reverselookup':    True,    # Reverse-resolve IPs to names for
                                    # more clues.
        "commonsubs":   [ "www", "web", "ns", "mail", "dns", "mx", "gw", "proxy",
                          "ssl", "fw", "gateway", "firewall", "www1", "www2"
                         ] # Common sub-domains to try.

    }

    # Option descriptions
    optdescs = {
        'resolveaffiliate': "Obtain IPs for confirmed affiliates?",
        'reverselookup': "Obtain new URLs and possible affiliates based on reverse-resolved IPs?",
        "commonsubs":   "Common sub-domains to try."
    }

    # Target
    baseDomain = None
    results = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.results = dict()
        self.baseDomain = target

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

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
        if self.results.has_key(eventData):
            sf.debug("Skipping " + eventData + " as already resolved.")
            return None
        else:
            self.results[eventData] = True

        try:
            if eventName != 'IP_ADDRESS':
                if '://' in eventData:
                    addrs = socket.gethostbyname_ex(sf.urlFQDN(eventData))
                else:
                    addrs = socket.gethostbyname_ex(eventData)
            else:
                addrs = socket.gethostbyaddr(eventData)
        except socket.error as e:
            sf.info("Unable to resolve " + eventData)
            return None
    
        # First element of tuple is primary hostname if requested name is 
        # a CNAME, or an IP is being reverse looked up
        if len(addrs[0]) > 0:
            host = addrs[0]
            sf.info("Found host: " + host)

        # Ignore cases where the IP resolves to the target domain
        if host.lower() == self.baseDomain:
            return None

        # If the returned hostname is on a different
        # domain to baseDomain, flag it as an affiliate
        if not host.lower().endswith(self.baseDomain):
            self.notifyListeners("AFFILIATE", eventData, host)
        else:
            self.notifyListeners("SUBDOMAIN", eventData, host)

        # In tests addr[1] was either always the requested lookup or empty

        # Now the IP addresses..
        if len(addrs[2]) > 0 and eventName != 'IP_ADDRESS':
            for ipaddr in addrs[2]:
                sf.info("Found IP Address: " + ipaddr)
                self.notifyListeners("IP_ADDRESS", eventData, ipaddr)

        return None

    def start(self):
        # Try resolving common names
        for sub in self.opts['commonsubs']:
            name = sub + "." + self.baseDomain
            try:
                addrs = socket.gethostbyname_ex(name)
                if len(addrs[0]) > 0:
                    host = addrs[0]
                    sf.info("Found host: " + host)
                    # If the returned hostname is on a different
                    # domain to baseDomain, flag it as an affiliate
                    if not host.lower().endswith(self.baseDomain):
                        self.notifyListeners("AFFILIATE", self.baseDomain, host)
                    else:
                        self.notifyListeners("SUBDOMAIN", self.baseDomain, host)
            except socket.error as e:
                sf.info("Unable to resolve " + name)

# End of sfp_dns class
