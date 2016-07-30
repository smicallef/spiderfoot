# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
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
# -------------------------------------------------------------------------------

import socket
import re
import dns
import urllib2
from netaddr import IPAddress, IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_dns(SpiderFootPlugin):
    """DNS:Footprint,Investigate:Networking::Performs a number of DNS checks to obtain Sub-domains/Hostnames, IP Addresses and Affiliates."""

    # Default options
    opts = {
        'netblocklookup': True,
        'maxnetblock': 24,
        'lookaside': True,
        'lookasidecount': 10,
        'onlyactive': True,
        'validatereverse': True,
        "skipcommononwildcard": True,
        "commonsubs": ["www", "web", "ns", "mail", "dns", "mx", "gw", "proxy",
                       "ssl", "fw", "gateway", "firewall", "www1", "www2",
                       "ns0", "ns1", "ns2", "dns0", "dns1", "dns2", "mx1", "mx2"
                       ]  # Common sub-domains to try.

    }

    # Option descriptions
    optdescs = {
        'skipcommononwildcard': "If wildcard DNS is detected, only attempt to look up the first common sub-domain from the common sub-domain list.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?",
        'maxnetblock': "Maximum owned netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'onlyactive': "Only report sub-domains/hostnames that resolve to an IP.",
        'validatereverse': "Validate that reverse-resolved hostnames still resolve back to that IP before considering them as aliases of your target.",
        'lookaside': "For each IP discovered, try and reverse look-up IPs 'next to' that IP for potential hostnames on the same subdomain/domain.",
        'lookasidecount': "If look-aside is enabled, the number of IPs on each 'side' of the IP to look up",
        'commonsubs': "Common sub-domains to try to resolve on the target subdomain/domain. Prefix with an '@' to iterate through a file containing sub-domains to try (one per line), e.g. @C:\subdomains.txt or @/home/bob/subdomains.txt. Or supply a URL to load the list from there."
    }

    events = dict()
    domresults = dict()
    hostresults = dict()
    resolveCache = dict()
    resolveCache6 = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.events = dict()
        self.domresults = dict()
        self.hostresults = dict()
        self.resolveCache = dict()
        self.resolveCache6 = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        self.sublist = self.opts['commonsubs']
        # User may have supplied a file or URL containing the subdomains
        if self.opts['commonsubs'][0].startswith("http://") or \
                self.opts['commonsubs'][0].startswith("https://") or \
                self.opts['commonsubs'][0].startswith("@"):
            self.sublist = self.sf.optValueToData(self.opts['commonsubs'][0])

    def enrichTarget(self, target):
        ret = list()
        # If it's an IP, get the hostname it reverse resolves to
        if target.getType() == "IP_ADDRESS":
            ret = self.resolveIP(target.getValue())
        if target.getType() == "INTERNET_NAME":
            ret = self.resolveHost(target.getValue())
        if target.getType() == "NETBLOCK_OWNER":
            ret = list()
            for addr in IPNetwork(target.getValue()):
                ipaddr = str(addr)
                if ipaddr.split(".")[3] in ['255', '0']:
                    continue
                if '255' in ipaddr.split("."):
                    continue
                ret.append(ipaddr)

                # Add the reverse-resolved hostnames as aliases too..
                names = self.resolveIP(ipaddr)

                if self.opts['validatereverse']:
                    for host in names:
                        chk = self.resolveHost(host)
                        if ipaddr in chk:
                            ret.append(host)
                else:
                    ret.extend(names)

        for host in ret:
            if self.sf.validIP(host):
                target.setAlias(host, "IP_ADDRESS")
            else:
                target.setAlias(host, "INTERNET_NAME")
                # If the target was a hostname/sub-domain, we can
                # add the domain as an alias for the target. But
                # not if the target was an IP or subnet.
                #if target.getType() == "INTERNET_NAME":
                #    dom = self.sf.hostDomain(host, self.opts['_internettlds'])
                #    target.setAlias(dom, "INTERNET_NAME")

        self.sf.debug("Aliases identified: " + str(target.getAliases()))

        return target

    # What events is this module interested in for input
    def watchedEvents(self):
        arr = ['RAW_DNS_RECORDS', 'SEARCH_ENGINE_WEB_CONTENT', 'RAW_RIR_DATA',
               'TARGET_WEB_CONTENT', 'LINKED_URL_INTERNAL', 'INTERNET_NAME',
               'IP_ADDRESS', 'NETBLOCK_OWNER', "DNS_TEXT"]
        return arr

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["IP_ADDRESS", "INTERNET_NAME", "PROVIDER_MAIL", "DOMAIN_NAME",
                "PROVIDER_DNS", "AFFILIATE_INTERNET_NAME", "RAW_DNS_RECORDS",
                "DNS_TEXT", "IPV6_ADDRESS"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventDataHash = self.sf.hashstring(eventData)
        addrs = None
        parentEvent = event

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventDataHash in self.events:
            return None

        self.events[eventDataHash] = True
        # Identify potential sub-domains/hostnames
        if eventName in ["SEARCH_ENGINE_WEB_CONTENT", "TARGET_WEB_CONTENT",
                         "LINKED_URL_INTERNAL", "RAW_RIR_DATA", "RAW_DNS_RECORDS", "DNS_TEXT"]:
            # If we've received a link or some raw data, extract potential sub-domains
            # from the data for resolving later.
            for name in self.getTarget().getNames():
                if self.checkForStop():
                    return None
                pat = re.compile("(%..)?([a-zA-Z0-9\-\.]+\." + name + ")", re.IGNORECASE)
                matches = re.findall(pat, urllib2.unquote(eventData))
                if matches is not None:
                    for match in matches:
                        self.processHost(match[1], parentEvent, affiliate=False)
            # Nothing left to do with internal links and raw data
            return None

        if eventName == 'NETBLOCK_OWNER' and self.opts['netblocklookup']:
            if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                self.sf.debug("Network size bigger than permitted: " +
                              str(IPNetwork(eventData).prefixlen) + " > " +
                              str(self.opts['maxnetblock']))
                return None

            if "::" in eventData:
                return None

            self.sf.debug("Looking up IPs in owned netblock: " + eventData)
            for ip in IPNetwork(eventData):
                ipaddr = str(ip)
                if "::" in ipaddr:
                    continue
                if ipaddr.split(".")[3] in ['255', '0']:
                    continue
                if '255' in ipaddr.split("."):
                    continue

                if self.checkForStop():
                    return None
                addrs = self.resolveIP(ipaddr)

                if len(addrs) > 0:
                    self.sf.debug("Found a reversed hostname from " + ipaddr +
                                  " (" + str(addrs) + ")")
                    for addr in addrs:
                        # Generate an event for the IP, then
                        # let the handling by this module take
                        # care of follow-up processing.
                        if self.checkForStop():
                            return None

                        self.processHost(ipaddr, parentEvent, False)
            return None

        # Handling INTERNET_NAME and IP_ADDRESS events..
        if eventName in ["IP_ADDRESS", "INTERNET_NAME"]:
            if eventName != 'IP_ADDRESS':
                if '://' in eventData:
                    addrs = self.resolveHost(self.sf.urlFQDN(eventData))
                else:
                    addrs = self.resolveHost(eventData)
            else:
                addrs = self.resolveIP(eventData)

            for addr in addrs:
                if self.checkForStop():
                    return None

                if self.getTarget().matches(addr):
                    self.processHost(addr, parentEvent, False)
                else:
                    self.processHost(addr, parentEvent, True)

            # Try to reverse-resolve IPs 'near' the identified IP
            if self.opts['lookaside'] and eventName == 'IP_ADDRESS':
                ip = IPAddress(eventData)
                minip = IPAddress(int(ip) - self.opts['lookasidecount'])
                maxip = IPAddress(int(ip) + self.opts['lookasidecount'])
                self.sf.debug("Lookaside max: " + str(maxip) + ", min: " + str(minip))
                s = int(minip)
                c = int(maxip)
                parentEventUp = parentEvent.sourceEvent

                while s <= c:
                    sip = str(IPAddress(s))
                    self.sf.debug("Attempting look-aside lookup of: " + sip)
                    if self.checkForStop():
                        return None

                    if sip in self.hostresults:
                        s += 1
                        continue

                    addrs = self.resolveIP(sip)
                    if len(addrs) == 0:
                        self.sf.debug("Look-aside resolve for " + sip + " failed.")
                        s += 1
                        continue

                    # Report addresses that resolve to hostnames on the same
                    # domain or sub-domain as the target.
                    if self.getTarget().matches(sip):
                        affil = False
                    else:
                        affil = True

                    # Generate the event for the look-aside IP, but don't let it re-trigger
                    # this module by adding it to self.events first.
                    self.events[sip] = True
                    ev = self.processHost(sip, parentEventUp, affil)

                    for addr in addrs:
                        if self.checkForStop():
                            return None

                        if addr == sip:
                            continue
                        # IP Addresses should be linked to whatever provided the IP
                        if self.sf.validIP(addr):
                            parent = parentEventUp
                        else:
                            # Hostnames from the IP need to be linked to the IP
                            parent = ev

                        if self.getTarget().matches(addr):
                            # Generate an event for the IP, then
                            # let the handling by this module take
                            # care of follow-up processing.
                            self.processHost(addr, parent, False)
                        else:
                            self.processHost(addr, parent, True)
                    s += 1
            return None

    # Resolve an IP
    def resolveIP(self, ipaddr):
        ret = list()
        self.sf.debug("Performing reverse-resolve of " + ipaddr)

        if ipaddr in self.resolveCache:
            self.sf.debug("Returning cached result for " + ipaddr + " (" +
                          str(self.resolveCache[ipaddr]) + ")")
            return self.resolveCache[ipaddr]

        try:
            addrs = self.sf.normalizeDNS(socket.gethostbyaddr(ipaddr))
            self.resolveCache[ipaddr] = addrs
            self.sf.debug("Resolved " + ipaddr + " to: " + str(addrs))
            return addrs
        except BaseException as e:
            self.sf.debug("Unable to resolve " + ipaddr + " (" + str(e) + ")")
            self.resolveCache[ipaddr] = list()
            return ret

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

    # Resolve a host to IPv6
    def resolveHost6(self, hostname):
        if hostname in self.resolveCache6:
            self.sf.debug("Returning IPv6 cached result for " + hostname + " (" +
                          str(self.resolveCache6[hostname]) + ")")
            return self.resolveCache6[hostname]

        try:
            addrs = list()
            res = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            for addr in res:
                if addr[4][0] not in addrs:
                    addrs.append(addr[4][0])
            if len(addrs) < 1:
                return None
            self.resolveCache6[hostname] = addrs
            self.sf.debug("Resolved " + hostname + " to IPv6: " + str(addrs))
            return addrs
        except BaseException as e:
            self.sf.debug("Unable to IPv6 resolve " + hostname + " (" + str(e) + ")")
            return list()

    # Process a host/IP, parentEvent is the event that represents this entity
    def processHost(self, host, parentEvent, affiliate=None):
        parentHash = self.sf.hashstring(parentEvent.data)
        if host not in self.hostresults:
            self.hostresults[host] = list(parentHash)
        else:
            if parentHash in self.hostresults[host] or parentEvent.data == host:
                self.sf.debug("Skipping host, " + host + ", already processed.")
                return None
            else:
                self.hostresults[host].append(parentHash)

        self.sf.debug("Found host: " + host)
        # If the returned hostname is aliaseed to our
        # target in some way, flag it as an affiliate
        if affiliate is None:
            affil = True
            if self.getTarget().matches(host):
                affil = False
            # If the IP the host resolves to is in our
            # list of aliases, 
            if not self.sf.validIP(host):
                for hostip in self.resolveHost(host):
                    if self.getTarget().matches(hostip):
                        affil = False
        else:
            affil = affiliate

        if affil:
            if self.sf.validIP(host):
                htype = "AFFILIATE_IPADDR"
            else:
                htype = "AFFILIATE_INTERNET_NAME"
        else:
            if self.sf.validIP(host):
                htype = "IP_ADDRESS"
            else:
                htype = "INTERNET_NAME"

        if htype.endswith("INTERNET_NAME") and self.opts['onlyactive']:
            if len(self.resolveHost(host)) == 0:
                return None

        # Report the host
        evt = SpiderFootEvent(htype, host, self.__name__, parentEvent)
        self.notifyListeners(evt)
        # Report the domain for that host
        if htype == "INTERNET_NAME":
            dom = self.sf.hostDomain(host, self.opts['_internettlds'])
            self.processDomain(dom, evt)

            # Try obtain the IPv6 address
            for ip6 in self.resolveHost6(host):
                evt6 = SpiderFootEvent("IPV6_ADDRESS", ip6, self.__name__, evt)
                self.notifyListeners(evt6)

        return evt

    def processDomain(self, domainName, parentEvent):
        if domainName not in self.domresults:
            self.domresults[domainName] = True
        else:
            self.sf.debug("Skipping domain, " + domainName + ", already processed.")
            return None

        domevt = SpiderFootEvent("DOMAIN_NAME", domainName, self.__name__, parentEvent)
        self.notifyListeners(domevt)

        self.sf.debug("Gathering DNS records for " + domainName)
        # Process the raw data alone
        recdata = dict()
        recs = {
            'MX': ['\S+\s+(?:\d+)?\s+IN\s+MX\s+\d+\s+(\S+)\.', 'PROVIDER_MAIL'],
            'NS': ['\S+\s+(?:\d+)?\s+IN\s+NS\s+(\S+)\.', 'PROVIDER_DNS'],
            'TXT': ['\S+\s+TXT\s+\"(.[^\"]*)"', 'DNS_TEXT']
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
                        self.sf.debug("Checking " + str(x) + " + against " + recs[rx][0])
                        pat = re.compile(recs[rx][0], re.IGNORECASE | re.DOTALL)
                        grps = re.findall(pat, str(x))
                        if len(grps) > 0:
                            for m in grps:
                                self.sf.debug("Matched: " + m)
                                strdata = unicode(m, 'utf-8', errors='replace')
                                evt = SpiderFootEvent(recs[rx][1], strdata,
                                                      self.__name__, domevt)
                                self.notifyListeners(evt)
                                if rec != "TXT" and not strdata.endswith(domainName):
                                    evt = SpiderFootEvent("AFFILIATE_INTERNET_NAME",
                                                          strdata, self.__name__, domevt)
                                    self.notifyListeners(evt)
                        else:
                            strdata = unicode(str(x), 'utf-8', errors='replace')
                            evt = SpiderFootEvent("RAW_DNS_RECORDS", strdata,
                                                  self.__name__, domevt)
                            self.notifyListeners(evt)
            except BaseException as e:
                self.sf.error("Failed to obtain DNS response for " + domainName +
                              "(" + rec + "): " + str(e), False)

        self.sf.debug("Iterating through possible sub-domains [" + str(self.sublist) + "]")
        count = 0
        wildcard = self.sf.checkDnsWildcard(domainName)
        # Try resolving common names
        for sub in self.sublist:
            if wildcard and self.opts['skipcommononwildcard'] and count > 0:
                self.sf.debug("Wildcard DNS detected, skipping iterating through remaining hosts.")
                return None

            if self.checkForStop():
                return None

            count += 1
            if sub != "":
                name = sub + "." + domainName
            else:
                continue

            # Skip hosts we've processed already
            if name in self.events.keys():
                continue

            if len(self.resolveHost(name)) > 0:
                self.processHost(name, domevt, affiliate=False)

# End of sfp_dns class
