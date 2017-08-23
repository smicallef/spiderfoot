# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dnsbrute
# Purpose:      SpiderFoot plug-in for attempting to resolve through brute-forcing
#               common hostnames.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/07/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import socket
import re
import dns
import urllib2
from netaddr import IPAddress, IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_dnsbrute(SpiderFootPlugin):
    """DNS Brute-force:Footprint,Investigate:DNS::Attempts to identify hostnames through brute-forcing common names."""


    # Default options
    opts = {
        "skipcommonwildcard": True,
        "domainonly": True,
        "commonsubs": ["www", "web", "ns", "mail", "dns", "mx", "gw", "proxy",
                       "ssl", "fw", "gateway", "firewall", "www1", "www2",
                       "ns0", "ns1", "ns2", "dns0", "dns1", "dns2", "mx1", "mx2"
                       ]  # Common sub-domains to try.

    }

    # Option descriptions
    optdescs = {
        'skipcommonwildcard': "If wildcard DNS is detected, only attempt to look up the first common sub-domain from the common sub-domain list.",
        'domainonly': "Only attempt to brute-force names on domain names, not hostnames (some hostnames are also sub-domains).",
        'commonsubs': "Common sub-domains to try to resolve on the target subdomain/domain. Prefix with an '@' to iterate through a file containing sub-domains to try (one per line), e.g. @C:\subdomains.txt or @/home/bob/subdomains.txt. Or supply a URL to load the list from there."
    }

    events = dict()
    resolveCache = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.events = dict()
        self.resolveCache = dict()
        self.__dataSource__ = "DNS"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        self.sublist = self.opts['commonsubs']
        # User may have supplied a file or URL containing the subdomains
        if self.opts['commonsubs'][0].startswith("http://") or \
                self.opts['commonsubs'][0].startswith("https://") or \
                self.opts['commonsubs'][0].startswith("@"):
            self.sublist = self.sf.optValueToData(self.opts['commonsubs'][0])


    # What events is this module interested in for input
    def watchedEvents(self):
        return ['INTERNET_NAME', 'DOMAIN_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["IP_ADDRESS", "INTERNET_NAME", "IPV6_ADDRESS"]

    # Resolve a host
    def resolveHost(self, hostname):
        if hostname in self.resolveCache:
            self.sf.debug("Returning cached result for " + hostname + " (" +
                          str(self.resolveCache[hostname]) + ")")
            return self.resolveCache[hostname]

        try:
            addrs = self.sf.normalizeDNS(socket.gethostbyname_ex(hostname))
            self.resolveCache[hostname] = addrs
            self.sf.debug("Resolved " + hostname + " to: " + str(addrs))
            return addrs
        except BaseException as e:
            self.sf.debug("Unable to resolve " + hostname + " (" + str(e) + ")")
            return list()

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventDataHash = self.sf.hashstring(eventData)
        parentEvent = event

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['domainonly'] and eventName == "INTERNET_NAME":
            return None

        if eventDataHash in self.events:
            return None

        self.events[eventDataHash] = True

        self.sf.debug("Iterating through possible sub-domains.")
        wildcard = self.sf.checkDnsWildcard(eventData)
        if self.opts['skipcommonwildcard'] and wildcard:
            self.sf.debug("Wildcard DNS detected.")
            return None

        # Try resolving common names
        for sub in self.sublist:
            if self.checkForStop():
                return None

            if sub == "":
                continue
            else:
                name = sub + "." + eventData

            # Skip hosts we've processed already
            if self.sf.hashstring(name) in self.events.keys():
                continue

            if len(self.resolveHost(name)) > 0:
                # Report the host
                evt = SpiderFootEvent("INTERNET_NAME", name, 
                                      self.__name__, parentEvent)
                self.notifyListeners(evt)

# End of sfp_dnsbrute class
