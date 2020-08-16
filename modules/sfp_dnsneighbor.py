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

from netaddr import IPAddress
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_dnsneighbor(SpiderFootPlugin):
    """DNS Look-aside:Footprint,Investigate:DNS::Attempt to reverse-resolve the IP addresses next to your target to see if they are related."""

    # Default options
    opts = {
        'lookasidecount': 10,
        'validatereverse': True
    }

    # Option descriptions
    optdescs = {
        'validatereverse': "Validate that reverse-resolved hostnames still resolve back to that IP before considering them as aliases of your target.",
        'lookasidecount': "If look-aside is enabled, the number of IPs on each 'side' of the IP to look up"
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

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if eventDataHash in self.events:
            return None

        self.events[eventDataHash] = True

        try:
            ip = IPAddress(eventData)
        except BaseException as e:
            self.sf.error("Invalid IP address received: " + eventData, False)
            return None

        try:
            minip = IPAddress(int(ip) - self.opts['lookasidecount'])
            maxip = IPAddress(int(ip) + self.opts['lookasidecount'])
        except BaseException as e:
            self.sf.error("Received an invalid IP address: " + eventData, False)
            return None

        self.sf.debug("Lookaside max: " + str(maxip) + ", min: " + str(minip))
        s = int(minip)
        c = int(maxip)

        while s <= c:
            sip = str(IPAddress(s))
            self.sf.debug("Attempting look-aside lookup of: " + sip)
            if self.checkForStop():
                return None

            if sip in self.hostresults or sip == eventData:
                s += 1
                continue

            addrs = self.sf.resolveIP(sip)
            if not addrs:
                self.sf.debug("Look-aside resolve for " + sip + " failed.")
                s += 1
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

            for addr in addrs:
                if self.checkForStop():
                    return None

                if addr == sip:
                    continue
                if self.sf.validIP(addr):
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
            s += 1

    def processHost(self, host, parentEvent, affiliate=None):
        parentHash = self.sf.hashstring(parentEvent.data)
        if host not in self.hostresults:
            self.hostresults[host] = [parentHash]
        else:
            if parentHash in self.hostresults[host] or parentEvent.data == host:
                self.sf.debug("Skipping host, " + host + ", already processed.")
                return None
            else:
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

        htype = None
        if affil:
            if self.sf.validIP(host):
                htype = "AFFILIATE_IPADDR"
        else:
            if self.sf.validIP(host):
                htype = "IP_ADDRESS"

        # If names were found, leave them to sfp_dnsresolve to resolve
        if not htype:
            return None

        # Report the host
        evt = SpiderFootEvent(htype, host, self.__name__, parentEvent)
        self.notifyListeners(evt)

        return evt

# End of sfp_dnsneighbor class
