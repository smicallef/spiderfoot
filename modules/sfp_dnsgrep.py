# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_dnsgrep
# Purpose:     SpiderFoot plug-in for retrieving domain names
#              from Rapid7 Sonar Project data sets using DNSGrep API.
#              - https://opendata.rapid7.com/about/
#              - https://blog.erbbysam.com/index.php/2019/02/09/dnsgrep/
#              - https://github.com/erbbysam/DNSGrep
#
# Author:      <bcoles@gmail.com>
#
# Created:     2020-03-14
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import socket
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_dnsgrep(SpiderFootPlugin):
    """DNSGrep:Footprint,Investigate,Passive:Passive DNS::Obtain Passive DNS information from Rapid7 Sonar Project using DNSGrep API."""

    # Default options
    opts = {
        'timeout': 30,
        'dns_resolve': True
    }

    # Option descriptions
    optdescs = {
        'timeout': "Query timeout, in seconds.",
        'dns_resolve': "DNS resolve each identified domain."
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]

    # Query the DNSGrep REST API
    def query(self, qry):
        params = {
            'q': '.' + qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }

        res = self.sf.fetchUrl('https://dns.bufferover.run/dns?' + urllib.parse.urlencode(params),
                               timeout=self.opts['timeout'],
                               useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.info("No results found for " + qry)
            return None

        if res['code'] != '200':
            self.sf.debug("Error retrieving search results for " + qry)
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from DNSGrep.", False)
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        data = self.query(eventData)

        if data is None:
            self.sf.info("No DNS records found for " + eventData)
            return None

        evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
        self.notifyListeners(evt)

        domains = list()

        # Forward DNS A records
        fdns = data.get("FDNS_A")
        if fdns:
            for r in fdns:
                try:
                    ip, domain = r.split(',')
                except:
                    continue

                domains.append(domain)

        # Reverse DNS records
        rdns = data.get("RDNS")
        if rdns:
            for r in rdns:
                try:
                    ip, domain = r.split(',')
                except:
                    continue

                domains.append(domain)

        for domain in domains:
            if domain in self.results:
                continue

            if not self.getTarget().matches(domain, includeParents=True):
                continue

            evt_type = "INTERNET_NAME"

            if self.opts["dns_resolve"] and not self.sf.resolveHost(domain):
                self.sf.debug("Host " + domain + " could not be resolved")
                evt_type += "_UNRESOLVED"

            evt = SpiderFootEvent(evt_type, domain, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_dnsgrep class
