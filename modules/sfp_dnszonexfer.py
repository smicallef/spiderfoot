# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dnszonexfer
# Purpose:      SpiderFoot plug-in for attempting a DNS zone transfer.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     22/08/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

import dns.query
import dns.zone
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_dnszonexfer(SpiderFootPlugin):
    """DNS Zone Transfer:Footprint,Investigate:DNS::Attempts to perform a full DNS zone transfer."""

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    events = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.events = self.tempStorage()
        self.__dataSource__ = "DNS"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['PROVIDER_DNS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["RAW_DNS_RECORDS", "INTERNET_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventDataHash = self.sf.hashstring(eventData)
        addrs = None
        parentEvent = event

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if srcModuleName == "sfp_dnszonexfer":
            self.sf.debug("Ignoring " + eventName + ", from self.")
            return None

        if eventDataHash in self.events:
            self.sf.debug("Skipping duplicate event for " + eventData)
            return None

        self.events[eventDataHash] = True

        res = dns.resolver.Resolver()
        if self.opts.get('_dnsserver', "") != "":
            res.nameservers = [self.opts['_dnsserver']]

        # Get the name server's IP. This is to avoid DNS leaks
        # when attempting to resolve the name server during
        # the zone transfer.
        if not self.sf.validIP(eventData):
            nsips = self.sf.resolveHost(eventData)
            if not nsips:
                return None

            if len(nsips) > 0:
                for n in nsips:
                    if self.sf.validIP(n):
                        nsip = n
                        break
            else:
                self.sf.error("Couldn't resolve the name server, " + \
                              "so not attempting zone transfer.", False)
                return None
        else:
            nsip = eventData

        for name in self.getTarget().getNames():
            self.sf.debug("Trying for name: " + name)
            try:
                ret = list()
                z = dns.zone.from_xfr(dns.query.xfr(nsip, name))
                names = list(z.nodes.keys())
                for n in names:
                    ret.append(z[n].to_text(n))

                evt = SpiderFootEvent("RAW_DNS_RECORDS", "\n".join(ret), self.__name__, parentEvent)
                self.notifyListeners(evt)

                # Try and pull out individual records
                for row in ret:
                    pat = re.compile("^(\S+)\.?\s+\d+\s+IN\s+[AC].*", re.IGNORECASE | re.DOTALL)
                    grps = re.findall(pat, row)
                    if len(grps) > 0:
                        for strdata in grps:
                            self.sf.debug("Matched: " + strdata)
                            if strdata.endswith("."):
                                strdata = strdata[:-1]
                            else:
                                strdata = strdata + "." + name

                            evt = SpiderFootEvent("INTERNET_NAME", strdata,
                                                  self.__name__, parentEvent)
                            self.notifyListeners(evt)

            except BaseException as e:
                self.sf.info("Unable to perform DNS zone transfer for " + eventData +
                              "(" + name + "): " + str(e))

# End of sfp_dnszonexfer class
