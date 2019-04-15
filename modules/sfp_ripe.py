# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ripe
# Purpose:      Queries Internet registryes like RIPE (incl. ARIN) to get 
#               netblocks and other bits of info.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     8/12/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import json
import math
from netaddr import IPAddress
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_ripe(SpiderFootPlugin):
    """RIPE:Footprint,Investigate,Passive:Public Registries::Queries the RIPE registry (includes ARIN data) to identify netblocks and other info."""


    # Default options
    opts = {}

    results = dict()
    currentEventSrc = None
    memCache = dict()
    nbreported = dict()
    keywords = None
    lastContent = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.memCache = dict()
        self.currentEventSrc = None
        self.nbreported = dict()
        self.lastContent = None

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'NETBLOCK_MEMBER', 'NETBLOCK_OWNER',
                'BGP_AS_OWNER', 'BGP_AS_MEMBER', 'INTERNET_NAME', 'DOMAIN_NAME', 'COMPANY_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["NETBLOCK_MEMBER", "NETBLOCK_OWNER", "BGP_AS_MEMBER",
                "RAW_RIR_DATA", "BGP_AS_OWNER", "BGP_AS_PEER", "PHONE_NUMBER", "HUMAN_NAME", "EMAILADDR", "AFFILIATE_IPADDR", 'DOMAIN_NAME']

    # Fetch content and notify of the raw data
    def fetchRir(self, url):
        if url in self.memCache:
            res = self.memCache[url]
        else:
            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])
            if res['content'] is not None:
                self.memCache[url] = res
                self.lastContent = res['content']
        return res

    # Get the netblock the IP resides in
    def ipNetblock(self, ipaddr):
        prefix = None

        res = self.fetchRir("https://stat.ripe.net/data/network-info/data.json?resource=" + ipaddr)
        if res['content'] is None:
            self.sf.debug("No Netblock info found/available for " + ipaddr + " at RIPE.")
            return None

        try:
            j = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        prefix = j["data"]["prefix"]
        if prefix is None:
            self.sf.debug("Could not identify network prefix.")
            return None

        return prefix

    # Get the AS owning the netblock
    def netblockAs(self, prefix):
        asn = None

        res = self.fetchRir("https://stat.ripe.net/data/whois/data.json?resource=" + prefix)
        if res['content'] is None:
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

        if asn == None:
            return None

        return str(asn)

    # Owner information about an AS
    def asOwnerInfo(self, asn):
        ownerinfo = dict()
        # Which keys to look for ownership information in (prefix)
        ownerkeys = [ "as", "value", "auth", "desc", "org", "mnt", "admin", "tech" ]

        res = self.fetchRir("https://stat.ripe.net/data/whois/data.json?resource=" + asn)
        if res['content'] is None:
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
                for k in ownerkeys:
                    if d['key'].lower().startswith(k):
                        if d["value"].lower() not in ["null", "none", "none specified"]:
                            if d["key"] in ownerinfo:
                                ownerinfo[d["key"]].append(d["value"])
                            else:
                                ownerinfo[d["key"]] = [d["value"]]

        self.sf.debug("Returning ownerinfo: " + str(ownerinfo))
        return ownerinfo

    # Netblocks owned by an AS
    def asNetblocks(self, asn):
        netblocks = list()

        res = self.fetchRir("https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + asn)
        if res['content'] is None:
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
        if res['content'] is None:
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

        if self.keywords is None:
            self.keywords = self.sf.domainKeywords(self.getTarget().getNames(),
                self.opts['_internettlds'])

        # Slightly more complex..
        rx = [
            '^{0}[-_/\'\"\\\.,\?\!\s\d]',
            '[-_/\'\"\\\.,\?\!\s]{0}$',
            '[-_/\'\"\\\.,\?\!\s]{0}[-_/\'\"\\\.,\?\!\s\d]'
        ]

        # Mess with the keyword as a last resort..
        keywordList = set()
        for kw in self.keywords:
            # Create versions of the keyword, esp. if hyphens are involved.
            keywordList.add(kw)
            keywordList.add(kw.replace('-', ' '))
            keywordList.add(kw.replace('-', '_'))
            keywordList.add(kw.replace('-', ''))

        for kw in keywordList:
            for r in rx:
                if re.match(r.format(kw), string, re.IGNORECASE) is not None:
                    return True

        return False

    # Owns the AS or not?
    def ownsAs(self, asn):
        # Determine whether the AS is owned by our target
        ownerinfo = self.asOwnerInfo(asn)
        owned = False

        if ownerinfo is not None:
            for k in ownerinfo.keys():
                items = ownerinfo[k]
                for item in items:
                    if self.findName(item.lower()):
                        owned = True
        return owned

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        # BGP AS Owner/Member -> BGP AS Peers
        if eventName.startswith("BGP_AS_"):
            neighs = self.asNeighbours(eventData)
            if neighs is None:
                self.sf.debug("No neighbors found to AS " + eventData)
                return None

            for nasn in neighs:
                if self.checkForStop():
                    return None

                ownerinfo = self.asOwnerInfo(nasn)
                ownertext = ''
                if ownerinfo is not None:
                    for k, v in ownerinfo.iteritems():
                        ownertext = ownertext + k + ": " + ', '.join(v) + "\n"

                    if len(ownerinfo) > 0:
                        evt = SpiderFootEvent("BGP_AS_PEER", nasn,
                                              self.__name__, event)
                        self.notifyListeners(evt)

        # BGP AS Owner -> Other Netblocks
        if eventName == "BGP_AS_OWNER":
            # Don't report additional netblocks from this AS if we've
            # already found this AS before.
            if eventData not in self.nbreported:
                # Find all the netblocks owned by this AS
                self.nbreported[eventData] = True
                netblocks = self.asNetblocks(eventData)
                if netblocks is not None:
                    for netblock in netblocks:
                        if netblock in self.results:
                            continue

                        # Technically this netblock was identified via the AS, not
                        # the original IP event, so link it to asevt, not event.
                        # Skip IPv6 for now
                        if ":" in netblock:
                            continue
                        evt = SpiderFootEvent("NETBLOCK_OWNER", netblock,
                                              self.__name__, event)
                        self.notifyListeners(evt)
                    evt = SpiderFootEvent("RAW_RIR_DATA", self.lastContent, self.__name__,
                                          event)
                    self.notifyListeners(evt)

            return None

        # NETBLOCK -> AS and other owned netblocks
        if eventName.startswith("NETBLOCK_"):
            # Get the BGP AS the netblock is a part of
            asn = self.netblockAs(eventData)
            if asn is None:
                self.sf.debug("Could not identify BGP AS for " + eventData)
                return None

            if eventName == "NETBLOCK_OWNER" and self.ownsAs(asn):
                asevt = SpiderFootEvent("BGP_AS_OWNER", asn, self.__name__, event)
                self.notifyListeners(asevt)
                evt = SpiderFootEvent("RAW_RIR_DATA", self.lastContent, self.__name__,
                                      event)
                self.notifyListeners(evt)
            else:
                asevt = SpiderFootEvent("BGP_AS_MEMBER", asn, self.__name__, event)
                self.notifyListeners(asevt)

            return None

        # IP ADDRESS -> NETBLOCK
        if eventName == "IP_ADDRESS":
            # Get the Netblock the IP is a part of
            prefix = self.ipNetblock(eventData)
            if prefix is None:
                self.sf.debug("Could not identify network prefix for " + eventData)
                return None

            # Get the BGP AS the netblock is a part of
            asn = self.netblockAs(prefix)
            if asn is None:
                self.sf.debug("Could not identify BGP AS for " + prefix)
                return None

            self.sf.info("Netblock found: " + prefix + "(" + asn + ")")
            evt = SpiderFootEvent("NETBLOCK_MEMBER", prefix, self.__name__, event)
            self.notifyListeners(evt)

        # INTERNET_NAME, DOMAIN_NAME, COMPANY_NAME -> EMAILADDR, PHONE_NUMBER, HUMAN_NAME, AFFILIATE_IPADDR
        if eventName == 'INTERNET_NAME' or eventName == 'DOMAIN_NAME' or eventName == 'COMPANY_NAME':
            
            search_query = eventData.replace(" ", "+AND+")

            res = self.fetchRir("https://apps.db.ripe.net/db-web-ui/api/rest/fulltextsearch/select?facet=true&format=xml&hl=true&q=(" + search_query + ")&start=0&wt=json")

            if res['content'] is None:
                self.sf.debug("Could not fetch free text search results for " + eventData + " at RIPE.")
                return None

            try:
                j = json.loads(res['content'])
            except Exception as e:
                self.sf.debug("Error processing JSON response.")
                return None

            numFound = j['result']['numFound']

            self.sf.debug("Got " + str(numFound) + " results from Ripe")

            if numFound > 0:

                #calculate pagination as only 10 results are shown per page
                current_page = 1
                target_page = int(math.ceil(float(numFound) / float(10)))
                
                self.sf.debug("Have to paginate through " + str(target_page) + " pages for all results")

                while current_page <= target_page:
                    self.sf.debug("Processing page " + str(current_page) + " out of " + str(target_page))

                    for result in j['result']['docs']:
                        for item in result['doc']['strs']:

                            if item['str']['name'] == "e-mail" or item['str']['name'] == "upd-to":
                                self.sf.debug("Got email for " + eventData)
                                email = item['str']['value']
                                evt = SpiderFootEvent("EMAILADDR", email, self.__name__, event)
                                self.notifyListeners(evt)
                                domain_name = email.split("@")[0]
                                evt = SpiderFootEvent("DOMAIN_NAME", domain_name, self.__name__, event)
                                self.notifyListeners(evt)

                            if item['str']['name'] == "phone":
                                self.sf.debug("Got email for " + eventData)
                                phone = item['str']['value']
                                evt = SpiderFootEvent("PHONE_NUMBER", phone, self.__name__, event)
                                self.notifyListeners(evt)

                            if item['str']['name'] == "person":
                                self.sf.debug("Got human name for " + eventData)
                                person = item['str']['value']
                                evt = SpiderFootEvent("HUMAN_NAME", person, self.__name__, event)
                                self.notifyListeners(evt)

                            #As ripe gives the IPs as ranges we need to increment from the start till the end ip
                            if item['str']['name'] == "lookup-key":
                                self.sf.debug("Got ips for " + eventData)
                                if " - " in item['str']['value']:
                                    self.sf.debug("Its an ip range")
                                    start_ip = item['str']['value'].split(" - ")[0]
                                    end_ip = item['str']['value'].split(" - ")[1]
                                    self.sf.debug("Start ip " + start_ip)
                                    self.sf.debug("End ip " + end_ip)
                                    current_ip_obj = IPAddress(str(start_ip))
                                    end_ip_obj = IPAddress(str(end_ip))
                                    self.sf.debug("Strings converted to objects")
                                    while current_ip_obj <= end_ip_obj:
                                        ipaddr = str(current_ip_obj)
                                        self.sf.debug("Storing ip " + ipaddr)
                                        evt = SpiderFootEvent("AFFILIATE_IPADDR", ipaddr, self.__name__, event)
                                        self.notifyListeners(evt)
                                        current_ip_obj += 1
                    
                    #If we havent reached the target page, fetch next page and increment the counter
                    if current_page < target_page:
                        self.sf.debug("Going to next page")
                        start_value = current_page * 10
                        res = self.fetchRir("https://apps.db.ripe.net/db-web-ui/api/rest/fulltextsearch/select?facet=true&format=xml&hl=true&q=(" + search_query + ")&wt=json&start=" + str(start_value))
                        if res['content'] is None:
                            self.sf.debug("Could not fetch free text search results for " + eventData + " at RIPE.")
                            return None

                        try:
                            j = json.loads(res['content'])
                        except Exception as e:
                            self.sf.debug("Error processing JSON response.")
                            return None

                        current_page += 1

                    #If we have reached the target page
                    if current_page == target_page:
                        current_page += 1


        return None


# End of sfp_ripe class
