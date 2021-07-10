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

import re
import urllib

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_dnsresolve(SpiderFootPlugin):

    meta = {
        'name': "DNS Resolver",
        'summary': "Resolves Hosts and IP Addresses identified, also extracted from raw content.",
        'flags': [""],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["DNS"]
    }

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

    events = None
    domresults = None
    hostresults = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.events = self.tempStorage()
        self.domresults = self.tempStorage()
        self.hostresults = self.tempStorage()
        self.__dataSource__ = "DNS"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def enrichTarget(self, target):
        ret = list()
        # If it's an IP, get the hostname it reverse resolves to
        self.sf.info("Identifying aliases for specified target(s)")
        ret = self.sf.resolveTargets(target, self.opts['validatereverse'])
        if not ret:
            return target

        for host in ret:
            self.sf.debug("Found an alias: " + host)
            if self.sf.validIP(host):
                target.setAlias(host, "IP_ADDRESS")
            elif self.sf.validIP6(host):
                target.setAlias(host, "IPV6_ADDRESS")
            else:
                target.setAlias(host, "INTERNET_NAME")
                idnahost = host.encode("idna")
                if idnahost != host:
                    target.setAlias(idnahost.decode('ascii', errors='replace'), "INTERNET_NAME")

                # If the target was a hostname/sub-domain, we can
                # add the domain as an alias for the target. But
                # not if the target was an IP or subnet.
                # if target.targetType == "INTERNET_NAME":
                #     dom = self.sf.hostDomain(host, self.opts['_internettlds'])
                #     target.setAlias(dom, "INTERNET_NAME")

        self.sf.info("Aliases identified: " + str(target.targetAliases))

        return target

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            # Events that need some kind of DNS treatment
            "CO_HOSTED_SITE", "AFFILIATE_INTERNET_NAME", "NETBLOCK_OWNER",
            "IP_ADDRESS", "IPV6_ADDRESS", "INTERNET_NAME", "AFFILIATE_IPADDR",
            # Events that may contain hostnames in their content
            "TARGET_WEB_CONTENT", "BASE64_DATA", "AFFILIATE_DOMAIN_WHOIS",
            "CO_HOSTED_SITE_DOMAIN_WHOIS", "DOMAN_WHOIS", "NETBLOCK_WHOIS",
            "LEAKSITE_CONTENT", "RAW_DNS_RECORDS", "RAW_FILE_META_DATA",
            "RAW_RIR_DATA", "SEARCH_ENGINE_WEB_CONTENT", "SIMILARDOMAIN_WHOIS",
            "SSL_CERTIFICATE_RAW", "SSL_CERTIFICATE_ISSUED", "TCP_PORT_OPEN_BANNER",
            "WEBSERVER_BANNER", "WEBSERVER_HTTPHEADERS"
        ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["IP_ADDRESS", "INTERNET_NAME", "AFFILIATE_INTERNET_NAME",
                "AFFILIATE_IPADDR", "DOMAIN_NAME", "IPV6_ADDRESS",
                "DOMAIN_NAME_PARENT", "CO_HOSTED_SITE_DOMAIN", "AFFILIATE_DOMAIN_NAME",
                "INTERNET_NAME_UNRESOLVED"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventDataHash = self.sf.hashstring(eventData)
        addrs = None
        parentEvent = event

        # Don't be recursive for names
        if srcModuleName in ["sfp_dnsresolve"] and "_NAME" in eventName:
            return

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventDataHash in self.events:
            self.sf.debug("Skipping duplicate event.")
            return
        self.events[eventDataHash] = True

        # Simply translates these to their domains
        if eventName in ["CO_HOSTED_SITE", "AFFILIATE_INTERNET_NAME"]:
            # If the co-host or affiliate is a domain name, generate
            # a domain event.
            if "AFFILIATE_" in eventName:
                ev = "AFFILIATE_DOMAIN_NAME"
            else:
                ev = "CO_HOSTED_SITE_DOMAIN"

            # What we've been provided might be a domain, so report it
            if self.sf.isDomain(eventData, self.opts['_internettlds']):
                evt = SpiderFootEvent(ev, eventData, self.__name__, parentEvent)
                self.notifyListeners(evt)

            # In case the domain of the provided host is different, report that too
            dom = self.sf.hostDomain(eventData, self.opts['_internettlds'])
            if dom == eventData or dom is None:
                return
            evt = SpiderFootEvent(ev, dom, self.__name__, parentEvent)
            self.notifyListeners(evt)
            return

        # Search for IPs/hosts in raw data
        if eventName not in ["CO_HOSTED_SITE", "AFFILIATE_INTERNET_NAME",
                             "NETBLOCK_OWNER", "IP_ADDRESS", "IPV6_ADDRESS",
                             "INTERNET_NAME", "AFFILIATE_IPADDR"]:
            data = urllib.parse.unquote(eventData).lower()
            # We get literal \n from RAW_RIR_DATA in cases where JSON responses
            # have been str()'d, breaking interpretation of hostnames.
            if eventName == 'RAW_RIR_DATA':
                data = re.sub(r'(\\x[0-f]{2}|\\n|\\r)', '\n', data)

            for name in self.getTarget().getNames():
                if self.checkForStop():
                    return

                offset = data.find(name)
                if offset < 0:
                    continue

                pat = re.compile(r"[^a-z0-9\-\.]([a-z0-9\-\.]*\." + name + ")", re.DOTALL | re.MULTILINE)
                while offset >= 0:
                    # If the target was found at the beginning of the content, skip past it
                    if offset == 0:
                        offset += len(name)
                        continue

                    if offset <= 100:
                        # Start from the beginning of the text
                        start = 0
                    else:
                        # Start looking for a host 100 chars before the target name
                        start = offset - 100

                    # Get up to 100 bytes before the name to try and get hostnames
                    chunkhost = data[start:(offset + start + len(name) + 1)]
                    try:
                        matches = re.findall(pat, chunkhost)
                        if matches:
                            for match in matches:
                                # Wildcard certs will come in as .blah.blah
                                if match.startswith("."):
                                    m = match[1:]
                                else:
                                    m = match
                                self.processHost(m, parentEvent, False)
                    except Exception as e:
                        self.sf.error(f"Error applying regex to data ({e})")

                    offset = data.find(name, start + len(chunkhost))

            # Nothing left to do with internal links and raw data
            return

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                    self.sf.debug("Network size bigger than permitted: "
                                  + str(IPNetwork(eventData).prefixlen) + " > "
                                  + str(self.opts['maxnetblock']))
                    return

            # Not handling IPv6 (yet)
            if "::" in eventData:
                return

            self.sf.debug(f"Looking up IPs in owned netblock: {eventData}")
            for ip in IPNetwork(eventData):
                ipaddr = str(ip)
                if "::" in ipaddr:
                    continue
                if ipaddr.split(".")[3] in ['255', '0']:
                    continue
                if '255' in ipaddr.split("."):
                    continue

                if self.checkForStop():
                    return

                addrs = self.sf.resolveIP(ipaddr)
                if addrs:
                    self.sf.debug(f"Found a reversed hostname from {ipaddr} ({addrs})")
                    for addr in addrs:
                        # Generate an event for the IP, then
                        # let the handling by this module take
                        # care of follow-up processing.
                        if self.checkForStop():
                            return

                        self.processHost(addr, parentEvent, False)
            return

        if eventName in ["IP_ADDRESS", "INTERNET_NAME", "IPV6_ADDRESS",
                         "AFFILIATE_IPADDR", "AFFILIATE_INTERNET_NAME"]:

            if "_NAME" in eventName:
                addrs = self.sf.resolveHost(eventData)
            else:
                addrs = self.sf.resolveIP(eventData)

            if not addrs:
                return

            addrs.append(eventData)

            # We now have a set of hosts/IPs to do something with.
            for addr in addrs:
                if self.checkForStop():
                    return

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

    # Process a host/IP, parentEvent is the event that represents this entity
    def processHost(self, host, parentEvent, affiliate=None):
        parentHash = self.sf.hashstring(parentEvent.data)
        if host not in self.hostresults:
            self.hostresults[host] = [parentHash]
        else:
            if parentHash in self.hostresults[host] or parentEvent.data == host:
                self.sf.debug("Skipping host, " + host + ", already processed.")
                return None

            self.hostresults[host] = self.hostresults[host] + [parentHash]

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
                hostips = self.sf.resolveHost(host)
                if hostips:
                    for hostip in hostips:
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
            elif self.sf.validIP6(host):
                htype = "IPV6_ADDRESS"
            else:
                htype = "INTERNET_NAME"

        if htype.endswith("INTERNET_NAME"):
            resolved = self.sf.resolveHost(host)
            if htype == "INTERNET_NAME" and not resolved:
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, parentEvent)
                self.notifyListeners(evt)
                return None

            if not resolved:
                return None

        # Report the host
        if host != parentEvent.data:
            evt = SpiderFootEvent(htype, host, self.__name__, parentEvent)
            self.notifyListeners(evt)
        else:
            evt = parentEvent

        # Report the domain for that host
        if htype == "INTERNET_NAME":
            dom = self.sf.hostDomain(host, self.opts['_internettlds'])
            if not dom:
                return None
            self.processDomain(dom, evt, False, host)

            # Try obtain the IPv6 address
            ip6s = self.sf.resolveHost6(host)
            if ip6s:
                for ip6 in ip6s:
                    parentHash = self.sf.hashstring(evt.data)
                    if ip6 not in self.hostresults:
                        self.hostresults[ip6] = [parentHash]
                    else:
                        if parentHash in self.hostresults[ip6] or evt.data == ip6:
                            self.sf.debug("Skipping host, " + ip6 + ", already processed.")
                            continue
                        else:
                            self.hostresults[ip6] = self.hostresults[ip6] + [parentHash]

                    evt6 = SpiderFootEvent("IPV6_ADDRESS", ip6, self.__name__, evt)
                    self.notifyListeners(evt6)

        if htype == "AFFILIATE_INTERNET_NAME":
            dom = self.sf.hostDomain(host, self.opts['_internettlds'])
            if not dom:
                return None
            if dom == host and not self.sf.isDomain(dom, self.opts['_internettlds']):
                return evt
            self.processDomain(dom, evt, True, host)

        return evt

    def processDomain(self, domainName, parentEvent, affil=False, host=None):
        if domainName in self.domresults:
            self.sf.debug(f"Skipping domain, {domainName}, already processed.")
            return None

        self.domresults[domainName] = True

        if affil:
            domevt = SpiderFootEvent("AFFILIATE_DOMAIN_NAME", domainName,
                                     self.__name__, parentEvent)
            self.notifyListeners(domevt)
            return None

        if self.getTarget().matches(domainName):
            domevt = SpiderFootEvent("DOMAIN_NAME", domainName,
                                     self.__name__, parentEvent)
            self.notifyListeners(domevt)
        else:
            # Only makes sense to link this event with a source event
            # that sits on the parent domain.
            if not host:
                return None
            if parentEvent.data.endswith("." + domainName):
                domevt = SpiderFootEvent("DOMAIN_NAME_PARENT", domainName,
                                         self.__name__, parentEvent)
                self.notifyListeners(domevt)
        return None

# End of sfp_dnsresolve class
