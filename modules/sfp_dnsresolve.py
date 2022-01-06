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
        'summary': "Resolves hosts and IP addresses identified, also extracted from raw content.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["DNS"]
    }

    # Default options
    opts = {
        'validatereverse': True,
        'skipcommononwildcard': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
    }

    # Option descriptions
    optdescs = {
        'skipcommononwildcard': "If wildcard DNS is detected, only attempt to look up the first common sub-domain from the common sub-domain list.",
        'validatereverse': "Validate that reverse-resolved hostnames still resolve back to that IP before considering them as aliases of your target.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?",
        'maxnetblock': "Maximum owned IPv4 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6netblock': "Maximum owned IPv6 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
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
        self.info("Identifying aliases for specified target(s)")
        ret = self.resolveTargets(target, self.opts['validatereverse'])
        if not ret:
            return target

        for host in ret:
            self.debug("Found an alias: " + host)
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

        self.info(f"Target aliases identified: {target.targetAliases}")

        return target

    def resolveTargets(self, target, validateReverse: bool) -> list:
        """Resolve alternative names for a given target.

        Args:
            target (SpiderFootTarget): target object
            validateReverse (bool): validate domain names resolve

        Returns:
            list: list of domain names and IP addresses
        """
        ret = list()

        if not target:
            return ret

        t = target.targetType
        v = target.targetValue

        if t in ["IP_ADDRESS", "IPV6_ADDRESS"]:
            r = self.sf.resolveIP(v)
            if r:
                ret.extend(r)
        if t == "INTERNET_NAME":
            r = self.sf.resolveHost(v)
            if r:
                ret.extend(r)
            r = self.sf.resolveHost6(v)
            if r:
                ret.extend(r)
        if t == "NETBLOCK_OWNER":
            max_netblock = self.opts['maxnetblock']
            if IPNetwork(v).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(v).prefixlen} > {max_netblock}")
                return list(set(ret))

            for addr in IPNetwork(v):
                if self.checkForStop():
                    return list(set(ret))

                ipaddr = str(addr)
                if ipaddr.split(".")[3] in ['255', '0']:
                    continue

                if '255' in ipaddr.split("."):
                    continue

                ret.append(ipaddr)

                # Add the reverse-resolved hostnames as aliases too
                names = self.sf.resolveIP(ipaddr)
                if not names:
                    continue

                if not validateReverse:
                    ret.extend(names)
                    continue

                for host in names:
                    chk = self.sf.resolveHost(host)
                    if chk and ipaddr in chk:
                        ret.append(host)
        if t == "NETBLOCKV6_OWNER":
            max_netblock = self.opts['maxv6netblock']
            if IPNetwork(v).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(v).prefixlen} > {max_netblock}")
                return list(set(ret))

            for addr in IPNetwork(v):
                if self.checkForStop():
                    return list(set(ret))

                ipaddr = str(addr)

                ret.append(ipaddr)

                # Add the reverse-resolved hostnames as aliases too
                names = self.sf.resolveIP(ipaddr)
                if not names:
                    continue

                if not validateReverse:
                    ret.extend(names)
                    continue

                for host in names:
                    chk = self.sf.resolveHost6(host)
                    if chk and ipaddr in chk:
                        ret.append(host)

        return list(set(ret))

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            # Events that need some kind of DNS treatment
            "CO_HOSTED_SITE", "AFFILIATE_INTERNET_NAME", "NETBLOCK_OWNER", "NETBLOCKV6_OWNER",
            "IP_ADDRESS", "IPV6_ADDRESS", "INTERNET_NAME", "AFFILIATE_IPADDR", "AFFILIATE_IPV6_ADDRESS",
            # Events that may contain hostnames in their content
            "TARGET_WEB_CONTENT", "BASE64_DATA", "AFFILIATE_DOMAIN_WHOIS",
            "CO_HOSTED_SITE_DOMAIN_WHOIS", "DOMAIN_WHOIS", "NETBLOCK_WHOIS",
            "LEAKSITE_CONTENT", "RAW_DNS_RECORDS", "RAW_FILE_META_DATA",
            "RAW_RIR_DATA", "SEARCH_ENGINE_WEB_CONTENT", "SIMILARDOMAIN_WHOIS",
            "SSL_CERTIFICATE_RAW", "SSL_CERTIFICATE_ISSUED", "TCP_PORT_OPEN_BANNER",
            "WEBSERVER_BANNER", "WEBSERVER_HTTPHEADERS"
        ]

    # What events this module produces
    def producedEvents(self):
        return ["IP_ADDRESS", "INTERNET_NAME", "AFFILIATE_INTERNET_NAME",
                "AFFILIATE_IPADDR", "AFFILIATE_IPV6_ADDRESS", "DOMAIN_NAME", "IPV6_ADDRESS", "INTERNAL_IP_ADDRESS",
                "DOMAIN_NAME_PARENT", "CO_HOSTED_SITE_DOMAIN", "AFFILIATE_DOMAIN_NAME",
                "INTERNET_NAME_UNRESOLVED"]

    # Handle events sent to this module
    def handleEvent(self, event) -> None:
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventDataHash = self.sf.hashstring(eventData)
        addrs = None
        parentEvent = event

        # Don't be recursive for names
        if srcModuleName in ["sfp_dnsresolve"] and "_NAME" in eventName:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventDataHash in self.events:
            self.debug("Skipping duplicate event.")
            return

        self.events[eventDataHash] = True

        # Parse Microsoft workaround "ipv6-literal.net" fake domain for IPv6 UNC paths
        # For internal use on Windows systems (should not resolve in DNS)
        if eventData.endswith(".ipv6-literal.net") and eventName == "AFFILIATE_INTERNET_NAME":
            ipv6 = eventData.split(".ipv6-literal.net")[0].replace('-', ':').replace('s', '%').split('%')[0]
            if self.sf.validIP6(ipv6):
                if self.getTarget().matches(ipv6):
                    evt = SpiderFootEvent("IPV6_ADDRESS", ipv6, self.__name__, parentEvent)
                else:
                    evt = SpiderFootEvent("AFFILIATE_IPV6_ADDRESS", ipv6, self.__name__, parentEvent)
                self.notifyListeners(evt)
            return

        # Convert ARPA in-addr.arpa address to IPv4 address
        if eventData.endswith(".in-addr.arpa") and eventName == "AFFILIATE_INTERNET_NAME":
            ipv4 = '.'.join(reversed(eventData.split('.in-addr.arpa')[0].split('.')))
            if self.sf.validIP(ipv4):
                if self.getTarget().matches(ipv4):
                    evt = SpiderFootEvent("IP_ADDRESS", ipv4, self.__name__, parentEvent)
                else:
                    evt = SpiderFootEvent("AFFILIATE_IPADDR", ipv4, self.__name__, parentEvent)
                self.notifyListeners(evt)

        # Simply translates these to their domains
        if eventName in ["CO_HOSTED_SITE", "AFFILIATE_INTERNET_NAME"]:
            # If the co-host or affiliate is a domain name, generate
            # a domain event.
            if eventName == "AFFILIATE_INTERNET_NAME":
                ev = "AFFILIATE_DOMAIN_NAME"
            else:
                ev = "CO_HOSTED_SITE_DOMAIN"

            # What we've been provided might be a domain, so report it
            if self.sf.isDomain(eventData, self.opts['_internettlds']):
                evt = SpiderFootEvent(ev, eventData, self.__name__, parentEvent)
                self.notifyListeners(evt)

            # In case the domain of the provided host is different, report that too
            dom = self.sf.hostDomain(eventData, self.opts['_internettlds'])
            if dom and dom != eventData:
                evt = SpiderFootEvent(ev, dom, self.__name__, parentEvent)
                self.notifyListeners(evt)

        # Resolve host names
        if eventName in ["INTERNET_NAME", "AFFILIATE_INTERNET_NAME"]:
            addrs = list()
            addrs.extend(self.sf.resolveHost(eventData))
            addrs.extend(self.sf.resolveHost6(eventData))

            if not addrs:
                return

            addrs.append(eventData)

            # We now have a set of hosts/IPs to do something with.
            for addr in set(addrs):
                if self.checkForStop():
                    return

                # IP addresses resolved from hosts are assumed
                # to be part of the target (non-affiliates),
                # unless the source event was an AFFILIATE event.
                affiliate = False
                if self.getTarget().matches(addr):
                    affiliate = False
                elif eventName.startswith("AFFILIATE_"):
                    affiliate = True
                self.processHost(addr, parentEvent, affiliate)

        # Reverse resolve IP addresses
        elif eventName in ["IP_ADDRESS", "IPV6_ADDRESS", "AFFILIATE_IPADDR", "AFFILIATE_IPV6_ADDRESS"]:
            addrs = self.sf.resolveIP(eventData)

            if not addrs:
                return

            addrs.append(eventData)

            # We now have a set of hosts/IPs to do something with.
            for addr in set(addrs):
                if self.checkForStop():
                    return

                # IP addresses resolved from hosts are assumed
                # to be part of the target (non-affiliates),
                # unless the source event was an AFFILIATE event.
                affiliate = False
                if self.getTarget().matches(addr):
                    affiliate = False
                elif eventName.startswith("AFFILIATE_"):
                    affiliate = True
                self.processHost(addr, parentEvent, affiliate)

        elif eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts['netblocklookup']:
                return

            if eventName == 'NETBLOCKV6_OWNER':
                max_netblock = self.opts['maxv6netblock']
            else:
                max_netblock = self.opts['maxnetblock']

            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

            self.debug(f"Looking up IPs in owned netblock: {eventData}")
            for ip in IPNetwork(eventData):
                if self.checkForStop():
                    return

                ipaddr = str(ip)

                # Skip 0 and 255 for IPv4 addresses
                if self.sf.validIP(ipaddr):
                    if ipaddr.split(".")[3] in ['255', '0']:
                        continue
                    if '255' in ipaddr.split("."):
                        continue

                addrs = self.sf.resolveIP(ipaddr)
                if not addrs:
                    continue

                self.debug(f"Found {len(addrs)} reversed hostnames from {ipaddr} ({addrs})")
                for addr in addrs:
                    if self.checkForStop():
                        return

                    # Generate an event for the IP, then
                    # let the handling by this module take
                    # care of follow-up processing.
                    self.processHost(addr, parentEvent, False)

        # For everything else (ie, raw data), search for IPs/hosts
        else:
            # ignore co-hosted sites
            if eventName == "CO_HOSTED_SITE":
                return

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
                    matches = None
                    try:
                        matches = re.findall(pat, chunkhost)
                    except Exception as e:
                        self.error(f"Error applying regex to data ({e})")

                    if matches:
                        for match in matches:
                            # Wildcard certs will come in as .blah.blah
                            if match.startswith("."):
                                m = match[1:]
                            else:
                                m = match
                            self.processHost(m, parentEvent, False)

                    offset = data.find(name, start + len(chunkhost))

    # Process a host/IP, parentEvent is the event that represents this entity
    def processHost(self, host, parentEvent, affiliate=None) -> None:
        parentHash = self.sf.hashstring(parentEvent.data)
        if host in self.hostresults:
            if parentHash in self.hostresults[host] or parentEvent.data == host:
                self.debug(f"Skipping host, {host}, already processed.")
                return
            self.hostresults[host] = self.hostresults[host] + [parentHash]
        else:
            self.hostresults[host] = [parentHash]

        self.debug(f"Found host: {host}")

        # If the returned hostname is aliased to our
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
                            break
                hostips6 = self.sf.resolveHost6(host)
                if hostips6:
                    for hostip6 in hostips6:
                        if self.getTarget().matches(hostip6):
                            affil = False
                            break
        else:
            affil = affiliate

        if affil:
            if self.sf.isValidLocalOrLoopbackIp(host):
                htype = "INTERNAL_IP_ADDRESS"
            elif self.sf.validIP(host):
                htype = "AFFILIATE_IPADDR"
            elif self.sf.validIP6(host):
                htype = "AFFILIATE_IPV6_ADDRESS"
            else:
                htype = "AFFILIATE_INTERNET_NAME"
        else:
            if self.sf.isValidLocalOrLoopbackIp(host):
                htype = "INTERNAL_IP_ADDRESS"
            elif self.sf.validIP(host):
                htype = "IP_ADDRESS"
            elif self.sf.validIP6(host):
                htype = "IPV6_ADDRESS"
            else:
                htype = "INTERNET_NAME"

        if htype in ["INTERNET_NAME", "AFFILIATE_INTERNET_NAME"]:
            if not self.sf.resolveHost(host) and not self.sf.resolveHost6(host):
                evt = SpiderFootEvent(f"{htype}_UNRESOLVED", host, self.__name__, parentEvent)
                self.notifyListeners(evt)
                return

        # Report the host
        if host != parentEvent.data:
            evt = SpiderFootEvent(htype, host, self.__name__, parentEvent)
            self.notifyListeners(evt)
        else:
            evt = parentEvent

        if htype == "INTERNET_NAME":
            dom = self.sf.hostDomain(host, self.opts['_internettlds'])
            if dom:
                self.processDomain(dom, evt, False, host)

            # Try obtain the IPv6 address
            ip6s = self.sf.resolveHost6(host)
            if not ip6s:
                return
            for ip6 in ip6s:
                parentHash = self.sf.hashstring(evt.data)
                if ip6 not in self.hostresults:
                    self.hostresults[ip6] = [parentHash]
                else:
                    if parentHash in self.hostresults[ip6] or evt.data == ip6:
                        self.debug(f"Skipping host, {ip6}, already processed.")
                        continue
                    self.hostresults[ip6] = self.hostresults[ip6] + [parentHash]

                evt6 = SpiderFootEvent("IPV6_ADDRESS", ip6, self.__name__, evt)
                self.notifyListeners(evt6)

        if htype == "AFFILIATE_INTERNET_NAME":
            dom = self.sf.hostDomain(host, self.opts['_internettlds'])
            if not dom:
                return
            if dom == host and not self.sf.isDomain(dom, self.opts['_internettlds']):
                return
            self.processDomain(dom, evt, True, host)

    def processDomain(self, domainName, parentEvent, affil=False, host=None) -> None:
        if domainName in self.domresults:
            self.debug(f"Skipping domain, {domainName}, already processed.")
            return

        self.domresults[domainName] = True

        if affil:
            domevt = SpiderFootEvent("AFFILIATE_DOMAIN_NAME", domainName,
                                     self.__name__, parentEvent)
            self.notifyListeners(domevt)
            return

        if self.getTarget().matches(domainName):
            domevt = SpiderFootEvent("DOMAIN_NAME", domainName,
                                     self.__name__, parentEvent)
            self.notifyListeners(domevt)
        else:
            # Only makes sense to link this event with a source event
            # that sits on the parent domain.
            if not host:
                return
            if parentEvent.data.endswith("." + domainName):
                domevt = SpiderFootEvent("DOMAIN_NAME_PARENT", domainName,
                                         self.__name__, parentEvent)
                self.notifyListeners(domevt)

# End of sfp_dnsresolve class
