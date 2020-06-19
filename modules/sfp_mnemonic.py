# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_mnemonic
# Purpose:     SpiderFoot plug-in for retrieving passive DNS information
#              from Mnemonic PassiveDNS API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2018-10-12
# Copyright:   (c) bcoles 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_mnemonic(SpiderFootPlugin):
    """Mnemonic PassiveDNS:Footprint,Investigate,Passive:Passive DNS::Obtain Passive DNS information from PassiveDNS.mnemonic.no."""

    # Default options
    opts = {
        'per_page': 500,
        'max_pages': 2,
        'timeout': 30,
        'maxage': 180,    # 6 months
        'verify': True,
        'cohostsamedomain': False,
        'maxcohost': 100
    }

    # Option descriptions
    optdescs = {
        'per_page': "Maximum number of results per page.",
        'max_pages': "Maximum number of pages of results to fetch.",
        'timeout': "Query timeout, in seconds.",
        'maxage': "The maximum age of the data returned, in days, in order to be considered valid.",
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
    }

    cohostcount = 0
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'IPV6_ADDRESS', 'INTERNET_NAME', 'DOMAIN_NAME']

    # What events this module produces
    def producedEvents(self):
        return ['IP_ADDRESS', 'IPV6_ADDRESS', 'CO_HOSTED_SITE',
                'INTERNET_NAME', 'DOMAIN_NAME']

    # Query the Mnemonic PassiveDNS v3 API
    # https://docs.mnemonic.no/display/public/API/PassiveDNS+Integration+Guide
    def query(self, qry, limit=500, offset=0):
        params = {
            'limit': str(limit),
            'offset': str(offset)
        }

        url = 'https://api.mnemonic.no/pdns/v3/' + qry + '?' + urllib.parse.urlencode(params)
        res = self.sf.fetchUrl(url, timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        # Unauthenticated users are limited to 100 requests per minute, and 1000 requests per day.
        time.sleep(0.75)

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
        if data['responseCode'] == 402:
            self.sf.debug("Error retrieving search results: Resource limit exceeded")
            self.errorState = True
            return None

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

        if self.errorState:
            return None

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        position = 0
        max_pages = int(self.opts['max_pages'])
        per_page = int(self.opts['per_page'])
        agelimit = int(time.time() * 1000) - (86400000 * self.opts['maxage'])
        cohostcount = 0
        cohosts = list()

        while position < (per_page * max_pages):
            if self.checkForStop():
                break

            if self.errorState:
                break

            data = self.query(eventData, limit=per_page, offset=position)

            if data is None:
                self.sf.info("No passive DNS data found for " + eventData)
                break

            position += per_page

            for r in data:
                if "*" in r['query'] or "%" in r['query']:
                    continue

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
                        if self.sf.validIP(r['answer']):
                            evt = SpiderFootEvent("IP_ADDRESS", r['answer'], self.__name__, event)
                            self.notifyListeners(evt)

                    if r['rrtype'] == 'aaaa':
                        if self.sf.validIP6(r['answer']):
                            evt = SpiderFootEvent("IPV6_ADDRESS", r['answer'], self.__name__, event)
                            self.notifyListeners(evt)

                    if r['rrtype'] == 'cname':
                        if not self.getTarget().matches(r['query'], includeParents=True):
                            continue

                        cohosts.append(r['query'])

        for co in set(cohosts):
            if self.checkForStop():
                return None

            if co in self.results:
                continue

            if eventName == "IP_ADDRESS" and (self.opts['verify'] and not self.sf.validateIP(co, eventData)):
                self.sf.debug("Host " + co + " no longer resolves to " + eventData)
                continue

            if not self.opts['cohostsamedomain']:
                if self.getTarget().matches(co, includeParents=True):
                    evt = SpiderFootEvent("INTERNET_NAME", co, self.__name__, event)
                    self.notifyListeners(evt)
                    if self.sf.isDomain(co, self.opts['_internettlds']):
                        evt = SpiderFootEvent("DOMAIN_NAME", co, self.__name__, event)
                        self.notifyListeners(evt)
                    continue

            if self.cohostcount < self.opts['maxcohost']:
                evt = SpiderFootEvent("CO_HOSTED_SITE", co, self.__name__, event)
                self.notifyListeners(evt)
                self.cohostcount += 1

# End of sfp_mnemonic class
