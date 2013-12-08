#-------------------------------------------------------------------------------
# Name:         sfp_ripe
# Purpose:      Some RIPE (http://stat.ripe.net) queries to get netblocks owned
#               and other bits of info.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     11/03/2013
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

class sfp_ripe(SpiderFootPlugin):
    """RIPE Query:Queries RIPE to identify netblocks and other info."""

    # Default options
    opts = { }

    # Target
    baseDomain = None
    results = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'SUBDOMAIN']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "AFFILIATE", "NETBLOCK", "RAW_RIPE_DATA",
            "BGP_AS", "PROVIDER_INTERNET" ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if self.results.has_key(eventData):
            sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if eventName == 'SUBDOMAIN':
            res = sf.fetchUrl("http://stat.ripe.net/data/dns-chain/data.json?resource=" + \
                eventData, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
            if res['content'] == None:
                sf.info("No RIPE info found/available for " + eventData)
                return None

            try:
                j = json.loads(res['content'])
            except Exception as e:
                sf.debug("Error processing JSON response.")
                return None

            nslist = j["data"]["authoritative_nameservers"]
            for ns in nslist:
                nsclean = ns.rstrip('.').lower()
                if not nsclean.endswith(self.baseDomain):
                    evt = SpiderFootEvent("AFFILIATE", nsclean, self.__name__, event)
                    self.notifyListeners(evt)

            # Just send the content off for others to process
            evt = SpiderFootEvent("RAW_RIPE_DATA", res['content'], self.__name__, event)
            self.notifyListeners(evt)
            return None

        # First get the netblock the IP resides on
        res = sf.fetchUrl("http://stat.ripe.net/data/network-info/data.json?resource=" + \
            eventData, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
        if res['content'] == None:
            sf.info("No RIPE info found/available for " + eventData)
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

        # Now see who owns the prefix
        res = sf.fetchUrl("http://stat.ripe.net/data/whois/data.json?resource=" + \
            prefix, timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
        if res['content'] == None:
            sf.info("No RIPE info found/available for prefix: " + prefix)
            return None

        keyword = sf.domainKeyword(self.baseDomain)
        content = res['content'].lower()
        #print keyword + " and " + self.baseDomain + " in: " + res['content']
        # Crude and probably prone to a lot of false positives. Need to revisit.
        if self.baseDomain in content or "\"" + keyword in content \
            or keyword +"\"" in content or keyword +"-" in content \
            or "-"+keyword in content:
            sf.info("Owned netblock found: " + prefix)
            evt = SpiderFootEvent("NETBLOCK", prefix, self.__name__, event)
            self.notifyListeners(evt)
            evt = SpiderFootEvent("RAW_RIPE_DATA", res['content'], self.__name__, event)
            self.notifyListeners(evt)

            # We now have a netblock owned by our target, we want to find
            # the AS hop before the AS owning this netblock to find the ISP.
            # 1. Parse the AS out of res['content']
            try:
                j = json.loads(res['content'])
                data = j["data"]["irr_records"][0]
            except Exception as e:
                sf.debug("Error processing JSON response.")
                return None
            asn = None
            for rec in data:
                if rec["key"] == "origin":
                    asn = rec["value"]
                    break

            # 2. Find all the netblocks owned by this AS
            if asn != None:
                res = sf.fetchUrl("http://stat.ripe.net/data/announced-prefixes/data.json?resource=" + \
                    "AS" + str(asn), timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
                if res['content'] == None:
                    sf.info("No RIPE info found/available for AS" + asn)
                else:
                    evt = SpiderFootEvent("BGP_AS", asn, self.__name__, event)
                    self.notifyListeners(evt)
                    try:
                        j = json.loads(res['content'])
                        data = j["data"]["prefixes"]
                    except Exception as e:
                        sf.debug("Error processing JSON response.")
                        return None
                    for rec in data:
                        pfx = rec["prefix"]
                        sf.info("Additional netblock found from same AS: " + pfx)
                        evt = SpiderFootEvent("NETBLOCK", pfx, self.__name__, event)
                        self.notifyListeners(evt)

                # 3. Find all the AS neighbours (the last hop before our target)
                res = sf.fetchUrl("http://stat.ripe.net/data/asn-neighbours/data.json?resource=" + \
                    "AS" + str(asn), timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
                if res['content'] == None:
                    sf.info("No RIPE info found/available for AS" + asn)
                else:
                    try:
                        j = json.loads(res['content'])
                        data = j["data"]["neighbours"]
                    except Exception as e:
                        sf.debug("Error processing JSON response.")
                        return None
                    for rec in data:
                        nasn = rec['asn']
                        res = sf.fetchUrl("http://stat.ripe.net/data/whois/data.json?resource=" + \
                            str(nasn), timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
                        if res['content'] == None:
                            sf.info("No RIPE info found/available for prefix: " + prefix)
                            return None
                        try:
                            j = json.loads(res['content'])
                            data = j["data"]["records"]
                        except Exception as e:
                            sf.debug("Error processing JSON response.")
                            return None

                        name = None
                        for rec in data:
                            for rrec in rec:
                                if rrec['key'] == "descr":
                                    name = rrec['value']
                                    break
                                if rrec['key'] == "OrgName":
                                    name = rrec['value']
                                    break

                            if name != None:
                                break

                        if name != None:
                            evt = SpiderFootEvent("PROVIDER_INTERNET", name,
                                 self.__name__, event)
                            self.notifyListeners(evt)                           
        else:
            # If they don't own the netblock they are serving from, then
            # the netblock owner is their Internet provider.
            try:
                j = json.loads(res['content'])
                data = j["data"]["irr_records"][0]
            except Exception as e:
                sf.debug("Error processing JSON response.")
                return None
            for rec in data:
                if rec['key'] == "descr":
                    evt = SpiderFootEvent("PROVIDER_INTERNET", rec['value'],
                        self.__name__, event)
                    self.notifyListeners(evt)
                    break

        return None

    def start(self):
        res = sf.fetchUrl("http://stat.ripe.net/data/dns-chain/data.json?resource=" + \
            self.baseDomain, timeout=self.opts['_fetchtimeout'], 
            useragent=self.opts['_useragent'])
        if res['content'] == None:
            sf.info("No RIPE info found/available for " + self.baseDomain)
            return None

        try:
            j = json.loads(res['content'])
        except Exception as e:
            sf.debug("Error processing JSON response.")
            return None

        nslist = j["data"]["authoritative_nameservers"]
        for ns in nslist:
            nsclean = ns.rstrip('.').lower()
            if not nsclean.endswith(self.baseDomain):
                evt = SpiderFootEvent("AFFILIATE", nsclean, self.__name__)
                self.notifyListeners(evt)

        # Just send the content off for others to process
        evt = SpiderFootEvent("RAW_RIPE_DATA", res['content'], self.__name__)
        self.notifyListeners(evt)
        return None
       
# End of sfp_ripe class
