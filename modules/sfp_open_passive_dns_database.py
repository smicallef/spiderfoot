# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_open_passive_dns_database
# Purpose:     SpiderFoot plug-in for retrieving passive DNS information
#              from pdns.daloo.de Open passive DNS database.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2020-02-22
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import time
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_open_passive_dns_database(SpiderFootPlugin):
    """Open Passive DNS Database:Footprint,Investigate,Passive:Passive DNS::Obtain passive DNS information from pdns.daloo.de Open passive DNS database."""

    # Default options
    opts = {
        "timeout": 30,
        "verify": True,
    }

    # Option descriptions
    optdescs = {
        "timeout": "Query timeout, in seconds.",
        "verify": "Verify identified domains still resolve to the associated specified IP address.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED", "IP_ADDRESS", "IPV6_ADDRESS"]

    # Query the Open Passive DNS Database for a domain
    def query(self, qry):
        params = {
            "alike": 1, # alike is required to find subdomains
            "q": qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }

        url = 'https://pdns.daloo.de/search.php?' + urllib.parse.urlencode(params)
        res = self.sf.fetchUrl(url, timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['code'] != "200":
            self.sf.debug("Error retrieving search results.")
            return None

        if res['content'] is None:
            self.sf.debug("No results found for " + qry)
            return None

        rows = re.findall(r'<tr>(.+?)</tr>', res['content'], re.DOTALL)

        if not rows:
            self.sf.debug("No passive DNS results for " + qry)
            return None

        data = list()

        for row in rows:
            columns = re.findall(r'<td.*?>(.*?)</td>', row, re.DOTALL)

            # 0 seems to indicate no genuine issue
            if len(columns) == 0:
                continue

            if len(columns) != 7:
                self.sf.error("Unexpected number of columns for row. Expected 7, Found " + str(len(columns)), False)
                continue

            data.append(columns)

        self.sf.info("Retrieved " + str(len(data)) + " DNS records")

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if srcModuleName == "sfp_open_passive_dns_database":
            self.sf.debug("Ignoring " + eventName + ", from self.")
            return None

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        data = self.query(eventData)

        if data is None or len(data) == 0:
            self.sf.info("No passive DNS data found for " + eventData)
            return None

        domains = list()

        for record in data:
            if self.checkForStop():
                return None

            if self.errorState:
                return None

            #first_seen = record[0]
            #last_seen = record[1]
            query_html = record[2]
            answer_type = record[3]
            answer_html = record[4]
            #ttl = record[5]
            #count = record[6]

            # Extract queries and answers from HTML, and append all in-scope records to the domains list for parsing
            r = re.findall(r'>(.+?)<', query_html, re.DOTALL)

            if len(r) == 0:
                continue

            query = r[0]

            if self.getTarget().matches(query, includeChildren=True, includeParents=True):
                domains.append(query)

            r = re.findall(r'>(.+?)<', answer_html, re.DOTALL)

            if len(r) == 0:
                continue

            answer = r[0]

            if self.getTarget().matches(answer, includeChildren=True, includeParents=True):
                domains.append(answer)

            # Answers for these records types are ignored,
            # as all in-scope records have already been added to the domains list for parsing
            if answer_type in ['PTR', 'NS', 'MX', 'CNAME', 'TXT', 'SOA']:
                continue

            if answer in self.results:
                continue

            if answer == 'NXDOMAIN':
                continue

            if answer_type == 'A':
                if not self.getTarget().matches(query, includeChildren=True, includeParents=True):
                    continue

                if not self.sf.validIP(answer):
                    self.sf.debug("Skipping invalid IP address " + answer)
                    continue

                if self.opts['verify'] and not self.sf.validateIP(query, answer):
                    self.sf.debug("Host " + query + " no longer resolves to " + answer)
                    continue

                evt = SpiderFootEvent("IP_ADDRESS", answer, self.__name__, event)
                self.notifyListeners(evt)

            if answer_type == 'AAAA':
                if not self.getTarget().matches(query, includeChildren=True, includeParents=True):
                    continue

                if not self.sf.validIP6(answer):
                    self.sf.debug("Skipping invalid IPv6 address " + answer)
                    continue

                if self.opts['verify'] and not self.sf.validateIP(query, answer):
                    self.sf.debug("Host " + query + " no longer resolves to " + answer)
                    continue
 
                evt = SpiderFootEvent("IPV6_ADDRESS", answer, self.__name__, event)
                self.notifyListeners(evt)

        for domain in set(domains):
            if self.checkForStop():
                return None

            if domain in self.results:
                continue

            if not self.getTarget().matches(domain, includeChildren=True, includeParents=True):
                continue

            if self.opts['verify'] and not self.sf.resolveHost(domain):
                self.sf.debug("Host " + domain + " could not be resolved")
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", domain, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("INTERNET_NAME", domain, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_open_passive_dns_database class
