# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_whois
# Purpose:      SpiderFoot plug-in for searching Whois servers for domain names
#               and netblocks identified.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2015
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

import whois
import ipwhois
from netaddr import IPAddress
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_whois(SpiderFootPlugin):
    """Whois:Footprint,Investigate,Passive:Public Registries::Perform a WHOIS look-up on domain names and owned netblocks."""

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "DOMAIN_NAME_PARENT", "NETBLOCK_OWNER",
                "CO_HOSTED_SITE_DOMAIN", "AFFILIATE_DOMAIN", "SIMILARDOMAIN" ]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["DOMAIN_WHOIS", "NETBLOCK_WHOIS", "DOMAIN_REGISTRAR",
                "CO_HOSTED_SITE_DOMAIN_WHOIS", "AFFILIATE_DOMAIN_WHOIS",
                "SIMILARDOMAIN_WHOIS"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        try:
            data = None
            if eventName != "NETBLOCK_OWNER":
                whoisdata = whois.whois(eventData)
                if whoisdata:
                    data = whoisdata.text
            else:
                qry = eventData.split("/")[0]
                ip = IPAddress(qry) + 1
                self.sf.debug("Querying for IP ownership of " + str(ip))
                r = ipwhois.IPWhois(ip)
                whoisdata = r.lookup_rdap(depth=1)
                if whoisdata:
                    data = str(whoisdata)
            if not data:
                self.sf.error("Unable to perform WHOIS on " + eventData, False)
                return None
        except BaseException as e:
            self.sf.error("Unable to perform WHOIS on " + eventData + ": " + str(e), False)
            return None

        # This is likely to be an error about being throttled rather than real data
        if len(data) < 250:
            self.sf.error("Throttling from Whois is probably happening.", False)
            return None

        if eventName.startswith("DOMAIN_NAME"):
            typ = "DOMAIN_WHOIS"
        if eventName.startswith("NETBLOCK"):
            typ = "NETBLOCK_WHOIS"
        if eventName.startswith("AFFILIATE_DOMAIN"):
            typ = "AFFILIATE_DOMAIN_WHOIS"
        if eventName.startswith("CO_HOSTED_SITE_DOMAIN"):
            typ = "CO_HOSTED_SITE_DOMAIN_WHOIS"
        if eventName == "SIMILARDOMAIN":
            typ = "SIMILARDOMAIN_WHOIS"

        rawevt = SpiderFootEvent(typ, data, self.__name__, event)
        self.notifyListeners(rawevt)

        if whoisdata.has_key('registrar'):
            if eventName.startswith("DOMAIN_NAME") and whoisdata['registrar'] is not None:
                evt = SpiderFootEvent("DOMAIN_REGISTRAR", whoisdata['registrar'],
                                      self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_whois class
