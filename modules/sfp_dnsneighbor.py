# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dnsneighbor
# Purpose:      SpiderFoot plug-in for gathering IP addresses from sub-domains
#               and hostnames identified, and optionally affiliates.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     07/07/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import ipaddress

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_dnsneighbor(SpiderFootPlugin):

    meta = {
        'name': "DNS Look-aside",
        'summary': "Attempt to reverse-resolve the IP addresses next to your target to see if they are related.",
        'flags': [],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["DNS"]
    }

    # Default options
    opts = {
        'lookasidebits': 4,
        'validatereverse': True
    }

    # Option descriptions
    optdescs = {
        'validatereverse': "Validate that reverse-resolved hostnames still resolve back to that IP before considering them as aliases of your target.",
        'lookasidebits': "If look-aside is enabled, the netmask size (in CIDR notation) to check. Default is 4 bits (16 hosts)."
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

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["AFFILIATE_IPADDR", "IP_ADDRESS"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventDataHash = self.sf.hashstring(eventData)
        addrs = None
        parentEvent = event

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventDataHash in self.events:
            return

        self.events[eventDataHash] = True

        try:
            address = ipaddress.ip_address(eventData)
            netmask = address.max_prefixlen - min(address.max_prefixlen, max(1, int(self.opts.get("lookasidebits"))))
            network = ipaddress.ip_network(f"{eventData}/{netmask}", strict=False)
        except ValueError:
            self.error(f"Invalid IP address received: {eventData}")
            return

        self.debug(f"Lookaside max: {network.network_address}, min: {network.broadcast_address}")

        for ip in network:
            sip = str(ip)
            self.debug("Attempting look-aside lookup of: " + sip)
            if self.checkForStop():
                return

            if sip in self.hostresults or sip == eventData:
                continue

            addrs = self.sf.resolveIP(sip)
            if not addrs:
                self.debug("Look-aside resolve for " + sip + " failed.")
                continue

            # Report addresses that resolve to hostnames on the same
            # domain or sub-domain as the target.
            if self.getTarget().matches(sip):
                affil = False
            else:
                affil = True
                for a in addrs:
                    if self.getTarget().matches(a):
                        affil = False

            # Generate the event for the look-aside IP, but don't let it re-trigger
            # this module by adding it to self.events first.
            self.events[sip] = True
            ev = self.processHost(sip, parentEvent, affil)

            if not ev:
                continue

            for addr in addrs:
                if self.checkForStop():
                    return

                if addr == sip:
                    continue

                if self.sf.validIP(addr) or self.sf.validIP6(addr):
                    parent = parentEvent
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

    def processHost(self, host, parentEvent, affiliate=None):
        parentHash = self.sf.hashstring(parentEvent.data)
        if host not in self.hostresults:
            self.hostresults[host] = [parentHash]
        else:
            if parentHash in self.hostresults[host] or parentEvent.data == host:
                self.debug("Skipping host, " + host + ", already processed.")
                return None
            self.hostresults[host] = self.hostresults[host] + [parentHash]

        self.debug("Found host: " + host)
        # If the returned hostname is aliased to our
        # target in some way, flag it as an affiliate
        if affiliate is None:
            affil = True
            if self.getTarget().matches(host):
                affil = False
            else:
                # If the IP the host resolves to is in our
                # list of aliases,
                if not self.sf.validIP(host) and not self.sf.validIP6(host):
                    hostips = self.sf.resolveHost(host)
                    if hostips:
                        for hostip in hostips:
                            if self.getTarget().matches(hostip):
                                affil = False
                                break
                    hostips6 = self.sf.resolveHost6(host)
                    if hostips6:
                        for hostip in hostips6:
                            if self.getTarget().matches(hostip):
                                affil = False
                                break
        else:
            affil = affiliate

        if not self.sf.validIP(host):
            return None

        if affil:
            htype = "AFFILIATE_IPADDR"
        else:
            htype = "IP_ADDRESS"

        # If names were found, leave them to sfp_dnsresolve to resolve
        if not htype:
            return None

        # Report the host
        evt = SpiderFootEvent(htype, host, self.__name__, parentEvent)
        self.notifyListeners(evt)

        return evt

# End of sfp_dnsneighbor class
