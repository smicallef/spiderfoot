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
import dns.resolver
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

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
                          "ssl", "fw", "gateway", "firewall", "www1", "www2",
                          "ns0", "ns1", "ns2", "dns0", "dns1", "dns2", "mx1", "mx2"
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
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        addrs = None

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
        except BaseException as e:
            sf.info("Unable to resolve " + eventData)
            return None

        for addr in addrs:
            if type(addr) == list:
                for host in addr:
                    self.processHost(host, event)
            else:
                self.processHost(addr, event)
 
        return None

    # Simple way to verify IPs.
    def validIP(self, address):
        parts = address.split(".")
        if len(parts) != 4:
            return False
        for item in parts:
            if not item.isdigit():
                return False
            if not 0 <= int(item) <= 255:
                return False
        return True

    def processHost(self, host, parentEvent=None):
        sf.info("Found host: " + host)
        # If the returned hostname is on a different
        # domain to baseDomain, flag it as an affiliate
        if not host.lower().endswith(self.baseDomain):
            if self.validIP(host):
                type = "IP_ADDRESS"
            else:
                type = "AFFILIATE"
        else:
            type = "SUBDOMAIN"

        evt = SpiderFootEvent(type, host, self.__name__, parentEvent)
        self.notifyListeners(evt)

    def start(self):
        sf.debug("Gathering MX, SOA and NS records.")
        # Process the raw data alone
        try:
            mx = dns.resolver.query(self.baseDomain, 'MX')
            soa = dns.resolver.query(self.baseDomain, 'SOA')
            ns = dns.resolver.query(self.baseDomain, 'NS')

            for data in [ns, mx, soa]:
                strdata = unicode(data.rrset.to_text(), 'utf-8', errors='replace') 
                evt = SpiderFootEvent("RAW_DATA", strdata, self.__name__)
                self.notifyListeners(evt)

            for rdata in mx:
                item = str(rdata.exchange).lower()[0:-1]
                evt = SpiderFootEvent("PROVIDER_MAIL", item, self.__name__)
                self.notifyListeners(evt)
                if not item.endswith(self.baseDomain):
                    evt = SpiderFootEvent("AFFILIATE", item, self.__name__)
                    self.notifyListeners(evt)

            for rdata in ns:
                item = str(rdata).lower()[0:-1]
                evt = SpiderFootEvent("PROVIDER_DNS", item, self.__name__)
                self.notifyListeners(evt)
                if not item.endswith(self.baseDomain):
                    evt = SpiderFootEvent("AFFILIATE", item, self.__name__)
                    self.notifyListeners(evt)
        except BaseException as e:
            sf.error("Failed to obtain MX, SOA and/or NS data out of DNS.", False)
            
        sf.debug("Iterating through possible sub-domains [" + str(self.opts['commonsubs']) + "]")
        # Try resolving common names
        for sub in self.opts['commonsubs']:
            if self.checkForStop():
                return None

            name = sub + "." + self.baseDomain
            try:
                addrs = socket.gethostbyname_ex(name)
                for addr in addrs:
                    if type(addr) == list:
                        for host in addr:
                            self.processHost(host)
                    else:
                        self.processHost(addr)

            except BaseException as e:
                sf.info("Unable to resolve " + name)


# End of sfp_dns class
