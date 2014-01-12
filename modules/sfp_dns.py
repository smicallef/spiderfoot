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
from netaddr import IPAddress, IPNetwork
import dns.resolver
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_dns(SpiderFootPlugin):
    """DNS:Performs a number of DNS checks to obtain Sub-domains/Hostnames, IP Addresses and Affiliates."""

    # Default options
    opts = {
        'reverselookup':    True,    # Reverse-resolve IPs to names for
                                    # more clues.
        'subnetlookup': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'lookaside': True,
        'lookasidecount': 10,
        "skipcommononwildcard": True,
        "commonsubs":   [ "www", "web", "ns", "mail", "dns", "mx", "gw", "proxy",
                          "ssl", "fw", "gateway", "firewall", "www1", "www2",
                          "ns0", "ns1", "ns2", "dns0", "dns1", "dns2", "mx1", "mx2"
                         ] # Common sub-domains to try.

    }

    # Option descriptions
    optdescs = {
        'skipcommononwildcard': "If wildcard DNS is detected, only attempt to look up the first common sub-domain from the common sub-domain list.",
        'reverselookup': "Obtain new URLs and possible affiliates based on reverse-resolved IPs?",
        'subnetlookup': "If reverse-resolving is enabled, look up all IPs on the same subnet for possible hosts on the same target domain?",
        'netblocklookup': "If reverse-resolving is enabled, look up all IPs on owned netblocks for possible hosts on the same target domain?",
        'maxnetblock': "Maximum netblock/subnet size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'lookaside': "For each IP discovered, try and reverse look-up IPs 'next to' that IP.",
        'lookasidecount': "If look-aside is enabled, the number of IPs on each 'side' of the IP to look up",
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
        arr = ['RAW_DNS_RECORDS', 'SEARCH_ENGINE_WEB_CONTENT', 'RAW_RIR_DATA',
            'TARGET_WEB_CONTENT', 'LINKED_URL_INTERNAL', 'SUBDOMAIN' ]
        if self.opts['reverselookup']:
            arr.extend(['IP_ADDRESS', 'NETBLOCK', 'IP_SUBNET'])
        return arr

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "IP_ADDRESS", "SUBDOMAIN", "PROVIDER_MAIL", 
            "PROVIDER_DNS", "AFFILIATE", "RAW_DNS_RECORDS" ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        addrs = None
        parentEvent = event

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.subresults.has_key(eventData):
            return None

        self.subresults[eventData] = True

        if eventName in [ "SEARCH_ENGINE_WEB_CONTENT", "TARGET_WEB_CONTENT",
            "LINKED_URL_INTERNAL", "RAW_RIR_DATA", "RAW_DNS_RECORDS" ]:
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

        if eventName in [ 'NETBLOCK', 'IP_SUBNET' ]:
            if eventName == 'NETBLOCK' and not self.opts['netblocklookup']:
                return None
            if eventName == 'IP_SUBNET' and not self.opts['subnetlookup']:
                return None

            if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                sf.debug("Network size bigger than permitted: " + \
                    str(IPNetwork(eventData).prefixlen) + " > " + \
                    str(self.opts['maxnetblock']))
                return None

            sf.debug("Looking up IPs in " + eventData)
            for ip in IPNetwork(eventData):
                if self.checkForStop():
                    return None
                ipaddr = str(ip)

                if self.results.has_key(ipaddr):
                    continue

                try:
                    addrs = socket.gethostbyaddr(ipaddr)
                    sf.debug("Found a reversed hostname from " + ipaddr + \
                        " (" + str(addrs) + ")")
                    for addr in addrs:
                        if type(addr) == list:
                            for host in addr:
                                # Don't report on anything on the same subnet if
                                # if doesn't resolve to something on the target
                                if not host.endswith(self.baseDomain) and \
                                    eventName == 'IP_SUBNET':
                                    continue
                                self.processHost(host, parentEvent)
                        else:
                            if not addr.endswith(self.baseDomain) and \
                                eventName == 'IP_SUBNET':
                                continue
                            self.processHost(addr, parentEvent)
                except Exception as e:
                    #sf.debug("Exception encountered: " + str(e))
                    continue

            return None

        # Handling SUBDOMAIN and IP_ADDRESS events..

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

        # Try to reverse-resolve
        if self.opts['lookaside'] and eventName == 'IP_ADDRESS':
            ip = IPAddress(eventData)
            minip = IPAddress(int(ip) - self.opts['lookasidecount'])
            maxip = IPAddress(int(ip) + self.opts['lookasidecount'])
            sf.debug("Lookaside max: " + str(maxip) + ", min: " + str(minip))
            s = int(minip)
            c = int(maxip)
            while s <= c:
                sip = str(IPAddress(s))
                if self.checkForStop():
                    return None

                if self.results.has_key(sip):
                    s = s + 1
                    continue

                try:
                    addrs = socket.gethostbyaddr(sip)
                    for addr in addrs:
                        if type(addr) == list:
                            for host in addr:
                                if host.endswith(self.baseDomain):
                                    self.processHost(host, parentEvent)
                        else:
                            if addr.endswith(self.baseDomain):
                                self.processHost(addr, parentEvent)
                except BaseException as e:
                    sf.debug("Look-aside lookup failed: " + str(e))
                s = s + 1
            
        return None

    # Resolve a host
    def resolveHost(self, hostname):
        try:
            return socket.gethostbyname_ex(hostname)
        except BaseException as e:
            sf.info("Unable to resolve " + eventData + " (" + str(e) + ")")
            return None

    def processHost(self, host, parentEvent=None):
        sf.debug("Found host: " + host)
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
            evt = SpiderFootEvent("RAW_DNS_DATA", strdata, self.__name__)
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
        # Also look up the base target itself
        sublist.append('')
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
            if sub != "":
                name = sub + "." + self.baseDomain
            else:
                name = self.baseDomain
            # Don't look up stuff twice
            if self.results.has_key(name):
                sf.debug("Skipping " + name + " as already resolved.")
                continue
            else:
                self.results[name] = True

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
                            if host not in self.results.keys():
                                self.processHost(host)
                                self.results[host] = True
                    else:
                        if addr not in self.results.keys():
                            self.processHost(addr)
                            self.results[addr] = True

# End of sfp_dns class
