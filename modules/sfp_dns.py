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

import socket
import sys
import re
import random
import dns
from netaddr import IPAddress, IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_dns(SpiderFootPlugin):
    """DNS:Performs a number of DNS checks to obtain Sub-domains/Hostnames, IP Addresses and Affiliates."""

    # Default options
    opts = {
        'subnetlookup': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'lookaside': True,
        'lookasidecount': 10,
        'onlyactive': True,
        "skipcommononwildcard": True,
        "commonsubs":   [ "www", "web", "ns", "mail", "dns", "mx", "gw", "proxy",
                          "ssl", "fw", "gateway", "firewall", "www1", "www2",
                          "ns0", "ns1", "ns2", "dns0", "dns1", "dns2", "mx1", "mx2"
                         ] # Common sub-domains to try.

    }

    # Option descriptions
    optdescs = {
        'skipcommononwildcard': "If wildcard DNS is detected, only attempt to look up the first common sub-domain from the common sub-domain list.",
        'subnetlookup': "Look up all IPs on identified subnets associated with your target for possible hosts on the same target subdomain/domain?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be 'owned' by your target for possible hosts on the same target subdomain/domain?",
        'maxnetblock': "Maximum netblock/subnet size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'onlyactive': "Only report sub-domains/hostnames that resolve to an IP.",
        'lookaside': "For each IP discovered, try and reverse look-up IPs 'next to' that IP for potential hostnames on the same subdomain/domain.",
        'lookasidecount': "If look-aside is enabled, the number of IPs on each 'side' of the IP to look up",
        "commonsubs":   "Common sub-domains to try to resolve on the target subdomain/domain. Prefix with an '@' to iterate through a file containing sub-domains to try (one per line), e.g. @C:\subdomains.txt or @/home/bob/subdomains.txt. Or supply a URL to load the list from there."
    }

    events = dict()
    domresults = dict()
    hostresults = dict()
    resolveCache = dict()

    def setup(self, sfc, userOpts=dict()):
        global sf

        sf = sfc
        self.events = dict()
        self.domresults = dict()
        self.hostresults = dict()
        self.resolveCache = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        self.sublist = self.opts['commonsubs']
        # User may have supplied a file or URL containing the subdomains
        if self.opts['commonsubs'][0].startswith("http://") or \
            self.opts['commonsubs'][0].startswith("https://") or \
            self.opts['commonsubs'][0].startswith("@"):
            self.sublist = sf.optValueToData(self.opts['commonsubs'][0])

    def enrichTarget(self, target):
        ret = None
        # If it's an IP, get the hostname it reverse resolves to
        if target.getType() == "IP_ADDRESS":
            ret = self.resolveIP(target.getValue())
        if target.getType() == "INTERNET_NAME":
            ret = self.resolveHost(target.getValue())
        if target.getType() == "IP_SUBNET":
            ret = list()
            for addr in IPNetwork(target.getValue()):
                ipaddr = str(addr)
                if ipaddr.split(".")[3] in [ '255', '0']:
                    continue
                if '255' in ipaddr.split("."):
                    continue
                ret.append(ipaddr)
                name = self.resolveIP(ipaddr)
                if name != None:
                    ret.append(name)

        if ret == None:
            return None

        for addr in ret:
            if type(addr) == list:
                for host in addr:
                    if sf.validIP(host):
                        target.setAlias(host, "IP_ADDRESS")
                    else:
                        target.setAlias(host, "INTERNET_NAME")
                        dom = sf.hostDomain(host, self.opts['_internettlds'])
                        target.setAlias(dom, "INTERNET_NAME")
            else:
                if sf.validIP(addr):
                    target.setAlias(addr, "IP_ADDRESS")
                else:
                    target.setAlias(addr, "INTERNET_NAME")
                    dom = sf.hostDomain(addr, self.opts['_internettlds'])
                    target.setAlias(dom, "INTERNET_NAME")
        
        sf.debug("Aliases identified: " + str(target.getAliases()))

        return target

    # What events is this module interested in for input
    def watchedEvents(self):
        arr = ['RAW_DNS_RECORDS', 'SEARCH_ENGINE_WEB_CONTENT', 'RAW_RIR_DATA',
            'TARGET_WEB_CONTENT', 'LINKED_URL_INTERNAL', 'INTERNET_NAME',
            'IP_ADDRESS', 'NETBLOCK', 'IP_SUBNET']
        return arr

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "IP_ADDRESS", "INTERNET_NAME", "PROVIDER_MAIL", "DOMAIN_NAME",
            "PROVIDER_DNS", "AFFILIATE_INTERNET_NAME", "RAW_DNS_RECORDS" ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        addrs = None
        parentEvent = event

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.events.has_key(eventData):
            return None

        self.events[eventData] = True

        # Identify potential sub-domains/hostnames
        if eventName in [ "SEARCH_ENGINE_WEB_CONTENT", "TARGET_WEB_CONTENT",
            "LINKED_URL_INTERNAL", "RAW_RIR_DATA", "RAW_DNS_RECORDS" ]:
            # If we've received a link or some raw data, extract potential sub-domains
            # from the data for resolving later.
            for name in self.getTarget().getNames():
                if self.checkForStop():
                    return None
                pat = re.compile("([a-zA-Z0-9\-\.]+\." + name + ")", re.IGNORECASE)
                matches = re.findall(pat, eventData)
                if matches != None:
                    for match in matches:
                        self.processHost(match, parentEvent)
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
                ipaddr = str(ip)
                if ipaddr.split(".")[3] in [ '255', '0']:
                    continue
                if '255' in ipaddr.split("."):
                    continue

                if self.checkForStop():
                    return None
                addrs = self.resolveIP(ipaddr)

                if addrs != None:
                    sf.debug("Found a reversed hostname from " + ipaddr + \
                        " (" + str(addrs) + ")")
                    for addr in addrs:
                        if type(addr) == list:
                            for host in addr:
                                # Don't report on anything on the same subnet if
                                # if doesn't resolve to something on the target
                                # domain/sub-domain.
                                # e.g. we don't report if 1.2.3.5 (IP next to
                                # target 1.2.3.4) resolves to a hostname on a
                                # completely differtent domain.
                                if not self.getTarget().matches(host) \
                                    and eventName == 'IP_SUBNET':
                                    continue
                                # Generate an event for the IP, then
                                # let the handling by this module take
                                # care of follow-up processing.
                                self.processHost(ipaddr, parentEvent)
                        else:
                            # Same as above comment
                            if not self.getTarget().matches(addr) \
                                and eventName == 'IP_SUBNET':
                                continue
                            self.processHost(ipaddr, parentEvent)

            return None

        # Handling INTERNET_NAME and IP_ADDRESS events..

        if eventName != 'IP_ADDRESS':
            if '://' in eventData:
                addrs = self.resolveHost(sf.urlFQDN(eventData))
            else:
                addrs = self.resolveHost(eventData)
        else:
            addrs = self.resolveIP(eventData)

        if addrs == None:
            return None
        else:
            for addr in addrs:
                if type(addr) == list:
                    for host in addr:
                        self.processHost(host, parentEvent)
                else:
                    self.processHost(addr, parentEvent)

        # Try to reverse-resolve IPs 'near' the identified IP
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

                if self.hostresults.has_key(sip):
                    s = s + 1
                    continue

                addrs = self.resolveIP(sip)
                if addrs == None:
                    sf.debug("Look-aside resolve for " + sip + " failed.")
                    s = s + 1
                    continue

                # Report addresses that resolve to hostnames on the same
                # domain or sub-domain as the target.
                for addr in addrs:
                    if type(addr) == list:
                        for host in addr:
                            if self.getTarget().matches(host):
                                # Generate an event for the IP, then
                                # let the handling by this module take
                                # care of follow-up processing.
                                self.processHost(sip, parentEvent)
                    else:
                        if self.getTarget().matches(addr):
                            self.processHost(sip, parentEvent)
                s = s + 1
            
        return None

    # Resolve an IP
    def resolveIP(self, ipaddr):
        ret = list()
        sf.debug("Performing reverse-resolve of " + ipaddr)

        if self.resolveCache.has_key(ipaddr):
            sf.debug("Returning cached result for " + ipaddr + " (" + \
                 str(self.resolveCache[ipaddr]) + ")")
            return self.resolveCache[ipaddr]

        try:
            addrs = socket.gethostbyaddr(ipaddr)
            for addr in addrs:
                if type(addr) == list:
                    for host in addr:
                        ret.append(host)
                else:
                    ret.append(addr)
            self.resolveCache[ipaddr] = ret
            return ret
        except BaseException as e:
            sf.info("Unable to resolve " + ipaddr + " (" + str(e) + ")")
            self.resolveCache[ipaddr] = None
            return None

    # Resolve a host
    def resolveHost(self, hostname):
        if self.resolveCache.has_key(hostname):
            sf.debug("Returning cached result for " + hostname + " (" + \
                str(self.resolveCache[hostname]) + ")" )
            return self.resolveCache[hostname]

        try:
            ret = socket.gethostbyname_ex(hostname)
            self.resolveCache[hostname] = ret
            return ret
        except BaseException as e:
            sf.info("Unable to resolve " + hostname + " (" + str(e) + ")")
            return None

    def processHost(self, host, parentEvent):
        if not self.hostresults.has_key(host):
            self.hostresults[host] = list(parentEvent.data)
        else:
            if parentEvent.data in self.hostresults[host]:
                sf.debug("Skipping host, " + host + ", already processed.")
                return None
            else:
                self.hostresults[host].append(parentEvent.data)

        sf.debug("Found host: " + host)
        # If the returned hostname is on a different
        # domain to the target, flag it as an affiliate
        if not self.getTarget().matches(host):
            if sf.validIP(host):
                htype = "AFFILIATE_IPADDR"
            else:
                htype = "AFFILIATE_INTERNET_NAME"
        else:
            if sf.validIP(host):
                htype = "IP_ADDRESS"
            else:
                htype = "INTERNET_NAME"
                
        if parentEvent != None:
            # Don't report back the same thing that was provided
            if htype == parentEvent.eventType and host == parentEvent.data:
                return None

        if htype.endswith("INTERNET_NAME") and self.opts['onlyactive']:
            if self.resolveHost(host) == None:
                return None

        # Report the host
        evt = SpiderFootEvent(htype, host, self.__name__, parentEvent)
        self.notifyListeners(evt)
        # Report the domain for that host
        if htype == "INTERNET_NAME":
            dom = sf.hostDomain(host, self.opts['_internettlds'])
            self.processDomain(dom, evt)

        return evt

    def processDomain(self, domainName, parentEvent):
        if not self.domresults.has_key(domainName):
            self.domresults[domainName] = True
        else:
            sf.debug("Skipping domain, " + domainName + ", already processed.")
            return None

        domevt = SpiderFootEvent("DOMAIN_NAME", domainName, self.__name__,
            parentEvent)
        self.notifyListeners(domevt)

        sf.debug("Gathering DNS records for " + domainName)
        # Process the raw data alone
        recdata = dict()
        recs = {
            'MX': ['\S+ \d+ IN MX \d+ (\S+)\.', 'PROVIDER_MAIL'],
            'NS': ['\S+ \d+ IN NS (\S+)\.', 'PROVIDER_DNS']
        }

        for rec in recs.keys():
            try:
                req = dns.message.make_query(domainName, dns.rdatatype.from_text(rec))
    
                if self.opts['_dnsserver'] != "":
                    n = self.opts['_dnsserver']
                else:
                    ns = dns.resolver.get_default_resolver()
                    n = ns.nameservers[0]
            
                res = dns.query.udp(req, n)
                for x in res.answer:
                    for rx in recs.keys():
                        sf.debug("Checking " + str(x) + " + against " + recs[rx][0])
                        pat = re.compile(recs[rx][0], re.IGNORECASE|re.DOTALL)
                        grps = re.findall(pat, str(x))
                        if len(grps) > 0:
                            for m in grps:
                                sf.debug("Matched: " +  m)
                                strdata = unicode(m, 'utf-8', errors='replace')
                                evt = SpiderFootEvent(recs[rx][1], strdata, 
                                    self.__name__)
                                self.notifyListeners(evt)
                                if not strdata.endswith(domainName):
                                    evt = SpiderFootEvent("AFFILIATE_INTERNET_NAME",
                                    strdata, self.__name__)
                                    self.notifyListeners(evt)
                        else:
                                strdata = unicode(str(x), 'utf-8', errors='replace')
                                evt = SpiderFootEvent("RAW_DNS_RECORDS", strdata, 
                                    self.__name__) 
                                self.notifyListeners(evt)
            except BaseException as e:
                sf.error("Failed to obtain DNS response for " + domainName + \
                    "(" + rec + "): " + str(e), False)

        sf.debug("Iterating through possible sub-domains [" + str(self.sublist) + "]")
        count = 0
        wildcard = sf.checkDnsWildcard(domainName)
        # Try resolving common names
        for sub in self.sublist:
            if wildcard and self.opts['skipcommononwildcard'] and count > 0:
                sf.debug("Wildcard DNS detected, skipping iterating through remaining hosts.")
                return None
                
            if self.checkForStop():
                return None

            count += 1
            if sub != "":
                name = sub + "." + domainName
            else:
                continue

            addrs = self.resolveHost(name)
            if addrs != None:
                for addr in addrs:
                    if type(addr) == list:
                        for host in addr:
                            self.processHost(host, domevt)
                    else:
                        self.processHost(addr, domevt)

# End of sfp_dns class
