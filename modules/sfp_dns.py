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
import random
import dns.resolver
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_dns(SpiderFootPlugin):
    """DNS:Performs a number of DNS checks to obtain Sub-domains/Hostnames, IP Addresses and Affiliates."""

    # Default options
    opts = {
        'resolveaffiliate': False,   # Get IPs for affiliate domains
        'reverselookup':    True,    # Reverse-resolve IPs to names for
                                    # more clues.
        "skipcommononwildcard": True,
        "commonsubs":   [ "www", "web", "ns", "mail", "dns", "mx", "gw", "proxy",
                          "ssl", "fw", "gateway", "firewall", "www1", "www2",
                          "ns0", "ns1", "ns2", "dns0", "dns1", "dns2", "mx1", "mx2"
                         ] # Common sub-domains to try.

    }

    # Option descriptions
    optdescs = {
        'skipcommononwildcard': "If wildcard DNS is detected, look up the first common sub-domain only.",
        'resolveaffiliate': "Obtain IPs for confirmed affiliates?",
        'reverselookup': "Obtain new URLs and possible affiliates based on reverse-resolved IPs?",
        "commonsubs":   "Common sub-domains to try. Prefix with an '@' to iterate through a file containing sub-domains to try (one per line), e.g. @C:\subdomains.txt or @/home/bob/subdomains.txt. Or supply a URL to load the list from there."
    }

    # Target
    baseDomain = None
    results = dict()
    subresults = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.results = dict()
        self.subresults = dict()
        self.baseDomain = target

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        arr = ['RAW_DATA', 'LINKED_URL_INTERNAL', 'SUBDOMAIN']
        if self.opts['resolveaffiliate']:
            arr.append('AFFILIATE')
        if self.opts['reverselookup']:
            arr.append('IP_ADDRESS')
        return arr

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "IP_ADDRESS", "SUBDOMAIN", "PROVIDER_MAIL", 
            "PROVIDER_DNS", "AFFILIATE" ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        addrs = None
        #if eventName == "RAW_DATA":
        #    parentEvent = event.sourceEvent
        #else:
        #    parentEvent = event
        parentEvent = event

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.subresults.has_key(eventData):
            return None

        self.subresults[eventData] = True

        if eventName in [ "RAW_DATA", "LINKED_URL_INTERNAL" ]:
            # If we've received a link or some raw data, extract potential sub-domains
            # from the data for resolving later.
            matches = re.findall("([a-zA-Z0-9\-\.]+\." + self.baseDomain + ")", eventData,
                re.IGNORECASE)

            if matches != None:
                for match in matches:
                    if match.lower().startswith("2f"):
                        continue

                    sf.info("Sub-domain/host found: " + match)
                    evt = SpiderFootEvent("SUBDOMAIN", match, self.__name__, parentEvent)
                    self.notifyListeners(evt)

            # Nothing left to do with internal links and raw data
            return None

        # Handling SUBDOMAIN, AFFILIATE and IP_ADDRESS events..

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
            sf.info("Unable to resolve " + eventData + " (" + str(e) + ")")
            return None

        for addr in addrs:
            if type(addr) == list:
                for host in addr:
                    self.processHost(host, parentEvent)
            else:
                self.processHost(addr, parentEvent)
 
        return None

    # Resolve a host
    def resolveHost(self, hostname):
        try:
            return socket.gethostbyname_ex(hostname)
        except BaseException as e:
            sf.info("Unable to resolve " + eventData + " (" + str(e) + ")")
            return None

    def processHost(self, host, parentEvent=None):
        sf.info("Found host: " + host)
        # If the returned hostname is on a different
        # domain to baseDomain, flag it as an affiliate
        if not host.lower().endswith(self.baseDomain):
            if sf.validIP(host):
                type = "IP_ADDRESS"
            else:
                type = "AFFILIATE"
        else:
            type = "SUBDOMAIN"

        if parentEvent != None:
            # Don't report back the same thing that was provided
            if type == parentEvent.eventType and host == parentEvent.data:
                return

        evt = SpiderFootEvent(type, host, self.__name__, parentEvent)
        self.notifyListeners(evt)

    def start(self):
        sf.debug("Gathering MX, SOA and NS records.")
        # Process the raw data alone
        recs = [ 'MX', 'NS', 'SOA' ]
        recdata = dict()

        for rec in recs:
            try:
                recdata[rec] = dns.resolver.query(self.baseDomain, rec)
            except BaseException as e:
                sf.error("Failed to obtain " + rec + " data out of DNS: " + str(e), False)

        for key in recdata.keys():
            strdata = unicode(recdata[key].rrset.to_text(), 'utf-8', errors='replace') 
            evt = SpiderFootEvent("RAW_DATA", strdata, self.__name__)
            self.notifyListeners(evt)

        if recdata.has_key('MX'):
            for rec in recdata['MX']:
                item = str(rec.exchange).lower()[0:-1]
                evt = SpiderFootEvent("PROVIDER_MAIL", item, self.__name__)
                self.notifyListeners(evt)
                if not item.endswith(self.baseDomain):
                    evt = SpiderFootEvent("AFFILIATE", item, self.__name__)
                    self.notifyListeners(evt)

        if recdata.has_key('NS'):
            for rec in recdata['NS']:
                item = str(rec).lower()[0:-1]
                evt = SpiderFootEvent("PROVIDER_DNS", item, self.__name__)
                self.notifyListeners(evt)
                if not item.endswith(self.baseDomain):
                    evt = SpiderFootEvent("AFFILIATE", item, self.__name__)
                    self.notifyListeners(evt)

        sublist = self.opts['commonsubs']
        # User may have supplied a file or URL containing the subdomains
        if self.opts['commonsubs'][0].startswith("http://") or \
            self.opts['commonsubs'][0].startswith("https://") or \
            self.opts['commonsubs'][0].startswith("@"):
            sublist = sf.optValueToData(self.opts['commonsubs'][0])
            
        sf.debug("Iterating through possible sub-domains [" + str(sublist) + "]")
        count = 0
        wildcard = sf.checkDnsWildcard(self.baseDomain)
        # Try resolving common names
        for sub in sublist:
            if wildcard and self.opts['skipcommononwildcard'] and count > 0:
                sf.debug("Wildcard DNS detected, skipping iterating through remaining hosts.")
                return None
                
            if self.checkForStop():
                return None

            count += 1
            name = sub + "." + self.baseDomain
            try:
                lookup = True
                addrs = socket.gethostbyname_ex(name)
            except BaseException as e:
                sf.info("Unable to resolve " + name + " (" + str(e) + ")")
                lookup = False

            if lookup:
                for addr in addrs:
                    if type(addr) == list:
                        for host in addr:
                            self.processHost(host)
                    else:
                        self.processHost(addr)

# End of sfp_dns class
