#-------------------------------------------------------------------------------
# Name:         sfp_ir
# Purpose:      Queries Internet registryes like RIPE (incl. ARIN) to get 
#               netblocks and other bits of info.
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
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_ir(SpiderFootPlugin):
    """Internet Registries:Queries Internet Registries to identify netblocks and other info."""

    # Default options
    opts = { }

    results = dict()
    currentEventSrc = None
    memCache = dict()
    nbreported = dict()
    keywords = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.memCache = dict()
        self.currentEventSrc = None
        self.nbreported = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "NETBLOCK", "RAW_RIR_DATA", "BGP_AS_OWNER", "PROVIDER_INTERNET" ]

    # Fetch content and notify of the raw data
    def fetchRir(self, url):
        if self.memCache.has_key(url):
            res = self.memCache[url]
        else:
            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
                useragent=self.opts['_useragent'])
            if res['content'] != None:
                self.memCache[url] = res
                evt = SpiderFootEvent("RAW_RIR_DATA", res['content'], self.__name__, 
                    self.currentEventSrc)
                self.notifyListeners(evt)
        return res

    # Get the netblock the IP resides in
    def ipNetblock(self, ipaddr):
        prefix = None

        res = self.fetchRir("https://stat.ripe.net/data/network-info/data.json?resource=" + ipaddr)
        if res['content'] == None:
            self.sf.debug("No Netblock info found/available for " + ipaddr + " at RIPE.")
            return None

        try:
            j = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        prefix = j["data"]["prefix"]
        if prefix == None:
            self.sf.debug("Could not identify network prefix.")
            return None

        return prefix

    # Get the AS owning the netblock
    def netblockAs(self, prefix):
        asn = None

        res = self.fetchRir("https://stat.ripe.net/data/whois/data.json?resource=" + prefix)
        if res['content'] == None:
            self.sf.debug("No AS info found/available for prefix: " + prefix + " at RIPE.")
            return None

        try:
            j = json.loads(res['content'])
            if len(j["data"]["irr_records"]) > 0:
                data = j["data"]["irr_records"][0]
            else:
                data = j["data"]["records"][0]
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
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
            self.sf.debug("No info found/available for ASN: " + asn + " at RIPE.")
            return None

        try:
            j = json.loads(res['content'])
            data = j["data"]["records"]
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        for rec in data:
            for d in rec:
                if d["key"].lower().startswith("org") or \
                    d["key"].lower().startswith("as") or \
                    d["key"].lower().startswith("descr") and \
                    d["value"].lower() not in [ "null", "none", "none specified" ]:
                    if ownerinfo.has_key(d["key"]):
                        ownerinfo[d["key"]].append(d["value"])
                    else:
                        ownerinfo[d["key"]] = [ d["value"] ]

        self.sf.debug("Returning ownerinfo: " + str(ownerinfo))
        return ownerinfo

    # Netblocks owned by an AS
    def asNetblocks(self, asn):
        netblocks = list()

        res = self.fetchRir("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + asn)
        if res['content'] == None:
            self.sf.debug("No netblocks info found/available for AS" + asn + " at RIPE.")
            return None

        try:
            j = json.loads(res['content'])
            data = j["data"]["prefixes"]
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        for rec in data:
            netblocks.append(rec["prefix"])
            self.sf.info("Additional netblock found from same AS: " + rec["prefix"])

        return netblocks

    # Neighbours to an AS
    def asNeighbours(self, asn):
        neighbours = list()

        res = self.fetchRir("https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS" + asn)
        if res['content'] == None:
            self.sf.debug("No neighbour info found/available for AS" + asn + " at RIPE.")
            return None

        try:
            j = json.loads(res['content'])
            data = j["data"]["neighbours"]
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        for rec in data:
            neighbours.append(str(rec['asn']))

        return neighbours

    # Determine whether there is a textual link between the target 
    # and the string supplied.
    def findName(self, string):
        # Simplest check to perform..
        if self.getTarget().getValue() in string:
            return True

        if self.keywords == None:
            self.keywords = self.sf.domainKeywords(self.getTarget().getNames(),
                self.opts['_internettlds'])

        # Slightly more complex..
        rx = [ 
            '^{0}[-_/\'\"\\\.,\?\! ]',
            '[-_/\'\"\\\.,\?\! ]{0}$',
            '[-_/\'\"\\\.,\?\! ]{0}[-_/\'\"\\\.,\?\! ]'
        ]

        # Mess with the keyword as a last resort..
        keywordList = list()
        for kw in self.keywords:
            # Create versions of the keyword, esp. if hyphens are involved.
            keywordList.append(kw)
            keywordList.append(kw.replace('-', ' '))
            keywordList.append(kw.replace('-', '_'))
            keywordList.append(kw.replace('-', ''))

        for kw in keywordList:
            self.sf.debug("Looking for keyword: " + kw)
            for r in rx:
                if re.match(r.format(kw), string, re.IGNORECASE) != None:
                    return True
        
        return False

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if self.results.has_key(eventData):
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        prefix = self.ipNetblock(eventData)
        if prefix == None:
            self.sf.debug("Could not identify network prefix.")
            return None

        asn = self.netblockAs(prefix)
        if asn == None:
            self.sf.debug("Could not identify netblock AS.")
            return None

        ownerinfo = self.asOwnerInfo(asn)
        owned = False

        if ownerinfo != None:
            for k in ownerinfo.keys():
                items = ownerinfo[k]
                for item in items:
                    if self.findName(item.lower()):
                        owned = True

        if owned:
            self.sf.info("Owned netblock found: " + prefix + "(" + asn + ")")
            evt = SpiderFootEvent("NETBLOCK", prefix, self.__name__, event)
            self.notifyListeners(evt)
            asevt = SpiderFootEvent("BGP_AS_OWNER", asn, self.__name__, event)
            self.notifyListeners(asevt)

            # Don't report additional netblocks from this AS if we've
            # already found this AS before.
            if not self.nbreported.has_key(asn):
                # 2. Find all the netblocks owned by this AS
                self.nbreported[asn] = True
                netblocks = self.asNetblocks(asn)
                if netblocks != None:
                    for netblock in netblocks:
                        if netblock == prefix:
                            continue
    
                        # Technically this netblock was identified via the AS, not
                        # the original IP event, so link it to asevt, not event.
                        evt = SpiderFootEvent("NETBLOCK", netblock, 
                            self.__name__, asevt)
                        self.notifyListeners(evt)

                # 3. Find all the AS neighbors to this AS
                neighs = self.asNeighbours(asn)
                if neighs == None:
                    return None

                for nasn in neighs:
                    if self.checkForStop():
                        return None

                    ownerinfo = self.asOwnerInfo(nasn)
                    ownertext = ''
                    if ownerinfo != None:
                        for k, v in ownerinfo.iteritems():
                            ownertext = ownertext + k + ": " + ', '.join(v) + "\n"
    
                    if len(ownerinfo) > 0:
                        evt = SpiderFootEvent("PROVIDER_INTERNET", ownertext,
                            self.__name__, asevt)
                        self.notifyListeners(evt)                           
        else:
            # If they don't own the netblock they are serving from, then
            # the netblock owner is their Internet provider.

            # Report the netblock instead as a subnet encapsulating the IP
            evt = SpiderFootEvent("IP_SUBNET", prefix, self.__name__, event)
            self.notifyListeners(evt)

            ownertext = ''
            if ownerinfo != None:
                for k, v in ownerinfo.iteritems():
                    ownertext = ownertext + k + ": " + ', '.join(v) + "\n"
                evt = SpiderFootEvent("PROVIDER_INTERNET", ownertext,
                    self.__name__, event)
                self.notifyListeners(evt)

        return None

# End of sfp_ir class
