# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_mnemonic
# Purpose:      SpiderFoot plug-in for retrieving passive DNS information
#               from Mnemonic PassiveDNS API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-12
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import socket
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_mnemonic(SpiderFootPlugin):
    """Mnemonic PassiveDNS:Footprint,Investigate,Passive:Passive DNS::Obtain Passive DNS information from PassiveDNS.mnemonic.no."""

    # Default options
    opts = {
        'limit': 1000,
        'timeout': 30,
        'maxage': 1095,   # 3 years
        'verify': True,
        'cohostsamedomain': False,
        'maxcohost': 100
    }

    # Option descriptions
    optdescs = {
        'limit': "Maximum number of results to fetch.",
        'timeout': "Query timeout, in seconds.",
        'maxage': "The maximum age of the data returned, in days, in order to be considered valid.",
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
    }

    cohostcount = 0
    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = "Mnemonic PassiveDNS"
        self.results = dict()
        self.cohostcount = 0                                                                                                                                                                                       

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # Verify a host resolves to an IP
    def validateIP(self, host, ip):
        try:
            addrs = socket.gethostbyname_ex(host)
        except BaseException as e:
            self.sf.debug("Unable to resolve " + host + ": " + str(e))
            return False

        for addr in addrs:
            if type(addr) == list:
                for a in addr:
                    if str(a) == ip:
                        return True
            else:
                if str(addr) == ip:
                    return True
        return False

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'INTERNET_NAME', 'DOMAIN_NAME']

    # What events this module produces
    def producedEvents(self):
        return ['IP_ADDRESS', 'IPV6_ADDRESS', 'CO_HOSTED_SITE', 'INTERNET_NAME']

    # Query the PassiveDNS Mnemonic REST API
    def query(self, qry, limit=1000, offset=0):
        url = "https://api.mnemonic.no/pdns/v3/" + qry
        url += "?limit=" + str(limit) + "&offset=" + str(offset)

        res = self.sf.fetchUrl(url, timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.info("No results found for " + qry)
            return None

        # Parse response content as JSON
        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        # Check the response is ok
        if not data['responseCode'] == 200:
            self.sf.debug("Error retrieving search results.")
            return None

        if 'data' not in data:
            self.sf.info("No results found for " + qry)
            return None

        if 'count' not in data:
            self.sf.info("No results found for " + qry)
            return None

        if 'size' not in data:
            self.sf.info("No results found for " + qry)
            return None

        # Check if there were any results
        size = data['size']
        count = data['count']

        if not count or not size:
            self.sf.info("No results found for " + qry)
            return None

        self.sf.info("Retrieved " + str(size) + " of " + str(count) + " results")

        return data['data']

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

        # Query Mnemonic PassiveDNS API
        data = self.query(eventData, limit=self.opts['limit'], offset=0)

        if data is None:
            self.sf.info("No passive DNS data found for " + eventData)
            return None

        agelimit = int(time.time() * 1000) - (86400000 * self.opts['maxage'])
        cohostcount = 0                                                                                                                                                                                                
        cohosts = list()                                                                                                                                                                                       

        for r in data:
            if r['lastSeenTimestamp'] < agelimit:
                self.sf.debug("Record found too old, skipping.")
                continue

            if eventName in [ 'IP_ADDRESS' ]:
                if r['rrtype'] == 'a':
                    cohosts.append(r['query'])

            if eventName in [ 'INTERNET_NAME', 'DOMAIN_NAME' ]:

                # Ignore PTR records
                if r['rrtype'] == 'ptr':
                    continue

                if r['rrtype'] == 'a':
                    evt = SpiderFootEvent("IP_ADDRESS", r['answer'], self.__name__, event)
                    self.notifyListeners(evt)

                if r['rrtype'] == 'aaaa':
                    evt = SpiderFootEvent("IPV6_ADDRESS", r['answer'], self.__name__, event)
                    self.notifyListeners(evt)

                if r['rrtype'] == 'cname':
                    if not self.getTarget().matches(r['query'], includeParents=True):
                        continue

                    if "*" in r['query'] or "%" in r['query']:
                        continue

                    cohosts.append(r['query'])

        for co in cohosts:
            if eventName == "IP_ADDRESS" and (self.opts['verify'] and not self.validateIP(co, eventData)):
                self.sf.debug("Host " + co + " no longer resolves to " + eventData)
                continue

            if co in self.results:
                continue

            if not self.opts['cohostsamedomain']:
                if self.getTarget().matches(co, includeParents=True):
                    evt = SpiderFootEvent("INTERNET_NAME", co, self.__name__, event)
                    self.notifyListeners(evt)
                    continue

            if self.cohostcount < self.opts['maxcohost']:
                evt = SpiderFootEvent("CO_HOSTED_SITE", co, self.__name__, event)
                self.notifyListeners(evt)
                self.cohostcount += 1

# End of sfp_mnemonic class
