# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dnsresolve
# Purpose:      SpiderFoot plug-in for extracting hostnames from identified data
#               and resolving them.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/07/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import socket
import re
import dns
import urllib2
from netaddr import IPAddress, IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_dnsresolve(SpiderFootPlugin):
    """DNS Resolver:Footprint,Investigate,Passive:DNS::Resolves Hosts and IP Addresses identified, also extracted from raw content."""

    # Default options
    opts = {
        'validatereverse': True,
        'skipcommononwildcard': True,
        'netblocklookup': True,
        'maxnetblock': 24
    }

    # Option descriptions
    optdescs = {
        'skipcommononwildcard': "If wildcard DNS is detected, only attempt to look up the first common sub-domain from the common sub-domain list.",
        'validatereverse': "Validate that reverse-resolved hostnames still resolve back to that IP before considering them as aliases of your target.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?",
        'maxnetblock': "Maximum owned netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
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
        self.__dataSource__ = "DNS"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

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
                idnahost = host.encode("idna")
                if idnahost != host:
                    target.setAlias(idnahost, "INTERNET_NAME")
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
        return [
                # Events that need some kind of DNS treatment
                "CO_HOSTED_SITE", "AFFILIATE_INTERNET_NAME", "NETBLOCK_OWNER",
                "IP_ADDRESS", "INTERNET_NAME", "AFFILIATE_IPADDR", 
                # Events that may contain hostnames in their content
                "TARGET_WEB_CONTENT", "BASE64_DATA", "AFFILIATE_DOMAIN_WHOIS",
                "CO_HOSTED_SITE_DOMAIN_WHOIS", "DOMAN_WHOIS", "NETBLOCK_WHOIS",
                "LEAKSITE_CONTENT", "RAW_DNS_RECORDS", "RAW_FILE_META_DATA",
                "SEARCH_ENGINE_WEB_CONTENT", "SIMILARDOMAIN_WHOIS",
                "SSL_CERTIFICATE_RAW", "SSL_CERTIFICATE_ISSUED", "TCP_PORT_OPEN_BANNER",
                "WEBSERVER_BANNER", "WEBSERVER_HTTPHEADERS"
                ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["IP_ADDRESS", "INTERNET_NAME", "AFFILIATE_INTERNET_NAME",
                "AFFILIATE_IPADDR", "DOMAIN_NAME", "IPV6_ADDRESS", 
                "DOMAIN_NAME_PARENT", "CO_HOSTED_SITE_DOMAIN", "AFFILIATE_DOMAIN",
                "INTERNET_NAME_UNRESOLVED"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventDataHash = self.sf.hashstring(eventData)
        addrs = None
        parentEvent = event

        # Don't be recursive, and trust that sfp_dnsbrute knows what it's doing
        if srcModuleName in [ "sfp_dnsresolve", "sfp_dnsbrute" ]:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventDataHash in self.events:
            self.sf.debug("Skipping duplicate event.")
            return None
        self.events[eventDataHash] = True

        # Simply translates these to their domains
        if eventName in ["CO_HOSTED_SITE", "AFFILIATE_INTERNET_NAME"]:
            dom = self.sf.hostDomain(eventData, self.opts['_internettlds'])
            if "AFFILIATE_" in eventName:
                ev = "AFFILIATE_DOMAIN"
            else:
                ev = "CO_HOSTED_SITE_DOMAIN"
            evt = SpiderFootEvent(ev, dom, self.__name__, parentEvent)
            self.notifyListeners(evt)
            return None

        # Search for IPs/hosts in raw data, but obviously nothing this module
        # already produces, as those things are already entities, not raw data.
        if eventName not in self.producedEvents():
            if type(eventData) in [dict, list]:
                eventDataStr = str(eventData)
            else:
                eventDataStr = eventData
            data = urllib2.unquote(eventDataStr)
            for name in self.getTarget().getNames():
                if self.checkForStop():
                    return None
                pat = re.compile("(%..)?([a-zA-Z0-9\-\.]+\." + name + ")", re.IGNORECASE)
                matches = re.findall(pat, data)
                if matches:
                    for match in matches:
                        self.processHost(match[1], parentEvent, False)
            # Nothing left to do with internal links and raw data
            return None

            if eventName == 'NETBLOCK_OWNER':
                if not self.opts['netblocklookup']:
                    return None
                else:
                    if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                        self.sf.debug("Network size bigger than permitted: " +
                                      str(IPNetwork(eventData).prefixlen) + " > " +
                                      str(self.opts['maxnetblock']))
                        return None

            # Not handling IPv6 (yet)
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

        if eventName in ["IP_ADDRESS", "INTERNET_NAME", 
                         "AFFILIATE_IPADDR", "AFFILIATE_INTERNET_NAME"]:

            if "_NAME" in eventName:
                addrs = self.resolveHost(eventData)
            else:
                addrs = self.resolveIP(eventData)

            # We now have a set of hosts/IPs to do something with.
            for addr in addrs:
                if self.checkForStop():
                    return None

                # Does the host/IP match to the original target?
                if self.getTarget().matches(addr):
                    self.processHost(addr, parentEvent, False)
                else:
                    # IP addresses resolved from hosts are assumed
                    # to be part of the target (non-affiliates).
                    if self.sf.validIP(addr) and "AFFILIATE_" not in eventName:
                        self.processHost(addr, parentEvent, False)
                    else:
                        self.processHost(addr, parentEvent, True)

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
        if not hostname:
            return list()

        if hostname in self.resolveCache:
            self.sf.debug("Returning cached result for " + hostname + " (" +
                          str(self.resolveCache[hostname]) + ")")
            return self.resolveCache[hostname]

        try:
            # IDNA-encode the hostname in case it contains unicode
            if type(hostname) != unicode:
                hostname = unicode(hostname, "utf-8", errors='replace').encode("idna")
            else:
                hostname = hostname.encode("idna")
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

        if htype.endswith("INTERNET_NAME"):
            resolved = len(self.resolveHost(host)) > 0
            if htype == "INTERNET_NAME" and not resolved:
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", host,
                                      self.__name__, parentEvent)
                self.notifyListeners(evt)
                return None

            if not resolved:
                return None

        if host != parentEvent.data and htype != parentEvent.eventType:
            evt = SpiderFootEvent(htype, host, self.__name__, parentEvent)
            self.notifyListeners(evt)
        else:
            evt = parentEvent

        # Report the domain for that host
        if htype == "INTERNET_NAME":
            dom = self.sf.hostDomain(host, self.opts['_internettlds'])
            self.processDomain(dom, evt)

            # Try obtain the IPv6 address
            for ip6 in self.resolveHost6(host):
                evt6 = SpiderFootEvent("IPV6_ADDRESS", ip6, self.__name__, evt)
                self.notifyListeners(evt6)

        if htype == "AFFILIATE_INTERNET_NAME":
            dom = self.sf.hostDomain(host, self.opts['_internettlds'])
            self.processDomain(dom, evt, True)

        return evt

    def processDomain(self, domainName, parentEvent, affil=False):
        if domainName not in self.domresults:
            self.domresults[domainName] = True
        else:
            self.sf.debug("Skipping domain, " + domainName + ", already processed.")
            return None

        if affil:
            domevt = SpiderFootEvent("AFFILIATE_DOMAIN", domainName,
                                     self.__name__, parentEvent)
            self.notifyListeners(domevt)
            return None

        if self.getTarget().matches(domainName):
            domevt = SpiderFootEvent("DOMAIN_NAME", domainName,
                                     self.__name__, parentEvent)
            self.notifyListeners(domevt)
        else:
            domevt = SpiderFootEvent("DOMAIN_NAME_PARENT", domainName,
                                     self.__name__, parentEvent)
            self.notifyListeners(domevt)
            return None

# End of sfp_dnsresolve class
