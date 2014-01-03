#-------------------------------------------------------------------------------
# Name:         sfp_ir
# Purpose:      Queries Internet registryes like RIPE and ARIN to get netblocks
#               and other bits of info.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     8/12/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
import json
import socket
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_ir(SpiderFootPlugin):
    """Internet Registries:Queries RIPE and ARIN to identify netblocks and other info."""

    # Default options
    opts = { }

    # Target
    baseDomain = None
    results = dict()
    currentEventSrc = None

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "NETBLOCK", "RAW_RIR_DATA", "BGP_AS", "PROVIDER_INTERNET" ]

    # Fetch content and notify of the raw data
    def fetchRir(self, url):
        res = sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
            useragent=self.opts['_useragent'])

        if res['content'] != None:
            evt = SpiderFootEvent("RAW_RIR_DATA", res['content'], self.__name__, 
                self.currentEventSrc)
            self.notifyListeners(evt)

        return res

    # Get the netblock the IP resides in
    def ipNetblock(self, ipaddr):
        prefix = None

        res = self.fetchRir("https://stat.ripe.net/data/network-info/data.json?resource=" + ipaddr)
        if res['content'] == None:
            sf.debug("No Netblock info found/available for " + ipaddr + " at RIPE.")
            return None

        try:
            j = json.loads(res['content'])
        except Exception as e:
            sf.debug("Error processing JSON response.")
            return None

        prefix = j["data"]["prefix"]
        if prefix == None:
            sf.debug("Could not identify network prefix.")
            return None

        return prefix

    # Get the AS owning the netblock
    def netblockAs(self, prefix):
        asn = None

        res = self.fetchRir("https://stat.ripe.net/data/whois/data.json?resource=" + prefix)
        if res['content'] == None:
            sf.debug("No AS info found/available for prefix: " + prefix + " at RIPE.")
            return None

        try:
            j = json.loads(res['content'])
            data = j["data"]["irr_records"][0]
        except Exception as e:
            sf.debug("Error processing JSON response.")
            return None

        for rec in data:
            if rec["key"] == "origin":
                asn = rec["value"]
                break

        return str(asn)

    # Owner information about an AS
    def asOwnerInfo(self, asn):
        ownerinfo = dict()

        res = self.fetchRir("https://stat.ripe.net/data/whois/data.json?resource=" + asn)
        if res['content'] == None:
            sf.debug("No info found/available for ASN: " + asn + " at RIPE.")
            return None

        try:
            j = json.loads(res['content'])
            data = j["data"]["records"]
        except Exception as e:
            sf.debug("Error processing JSON response.")
            return None

        for rec in data:
            for d in rec:
                if d["key"].startswith("Org") or d["key"].startswith("AS"):
                    ownerinfo[d["key"]] = d["value"]

        return ownerinfo

    # Netblocks owned by an AS
    def asNetblocks(self, asn):
        netblocks = list()

        res = self.fetchRir("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + asn)
        if res['content'] == None:
            sf.debug("No netblocks info found/available for AS" + asn + " at RIPE.")
            return None

        try:
            j = json.loads(res['content'])
            data = j["data"]["prefixes"]
        except Exception as e:
            sf.debug("Error processing JSON response.")
            return None

        for rec in data:
            netblocks.append(rec["prefix"])
            sf.info("Additional netblock found from same AS: " + rec["prefix"])

        return netblocks

    # Neighbours to an AS
    def asNeighbours(self, asn):
        neighbours = list()

        res = self.fetchRir("https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS" + asn)
        if res['content'] == None:
            sf.debug("No neighbour info found/available for AS" + asn + " at RIPE.")
            return None

        try:
            j = json.loads(res['content'])
            data = j["data"]["neighbours"]
        except Exception as e:
            sf.debug("Error processing JSON response.")
            return None

        for rec in data:
            neighbours.append(str(rec['asn']))

        return neighbours

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if self.results.has_key(eventData):
            sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        prefix = self.ipNetblock(eventData)
        if prefix == None:
            sf.debug("Could not identify network prefix.")
            return None

        asn = self.netblockAs(prefix)
        if asn == None:
            sf.debug("Could not identify netblock AS.")
            return None

        ownerinfo = self.asOwnerInfo(asn)
        keyword = sf.domainKeyword(self.baseDomain).lower()
        owned = False
        for k in ownerinfo.keys():
            item = ownerinfo[k]
            if self.baseDomain in item or "\"" + keyword in item \
                or keyword +"\"" in item or keyword +"-" in item \
                or "-"+keyword in item:
                owned = True

        if owned:
            sf.info("Owned netblock found: " + prefix + "(" + asn + ")")
            evt = SpiderFootEvent("NETBLOCK", prefix, self.__name__, event)
            self.notifyListeners(evt)
            evt = SpiderFootEvent("BGP_AS", asn, self.__name__, event)
            self.notifyListeners(evt)

            # 2. Find all the netblocks owned by this AS
            netblocks = self.asNetblocks(asn)
            for netblock in netblocks:
                evt = SpiderFootEvent("NETBLOCK", netblock, self.__name__, event)
                self.notifyListeners(evt)

                neighs = self.asNeighbours(asn)
                for nasn in neighs:
                    ownerinfo = self.asOwnerInfo(nasn)
                    if len(ownerinfo) > 0:
                        evt = SpiderFootEvent("PROVIDER_INTERNET", str(ownerinfo),
                            self.__name__, event)
                        self.notifyListeners(evt)                           
        else:
            # If they don't own the netblock they are serving from, then
            # the netblock owner is their Internet provider.
            evt = SpiderFootEvent("PROVIDER_INTERNET", str(ownerinfo),
                self.__name__, event)
            self.notifyListeners(evt)

        return None

# End of sfp_ir class
