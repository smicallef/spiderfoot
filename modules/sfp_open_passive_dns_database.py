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

import re
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_open_passive_dns_database(SpiderFootPlugin):

    meta = {
        'name': "Open Passive DNS Database",
        'summary': "Obtain passive DNS information from pdns.daloo.de Open passive DNS database.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "http://pdns.daloo.de/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "http://pdns.daloo.de/faq.php"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=http://pdns.daloo.de/",
            'logo': "https://www.google.com/s2/favicons?domain=http://pdns.daloo.de/",
            'description': "This is a personal project to track DNS responses. "
            "You can use the DNS resolver to add data to it or just browse what the crawler found. "
            "I mainly did it because I found no really open database.",
        }
    }

    opts = {
        "timeout": 30,
        "verify": True,
    }

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

    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    def producedEvents(self):
        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED", "IP_ADDRESS", "IPV6_ADDRESS"]

    def query(self, qry):
        """Query the Open Passive DNS Database for subdomains of a domain name.

        Args:
            qry (str): Domain name

        Returns:
            list: List of subdomain details
        """
        params = {
            "alike": 1,  # alike is required to find subdomains
            "q": qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }

        url = 'https://pdns.daloo.de/search.php?' + urllib.parse.urlencode(params)
        res = self.sf.fetchUrl(url, timeout=self.opts['timeout'], useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['code'] != "200":
            self.debug("Error retrieving search results.")
            return None

        if res['content'] is None:
            self.debug("No results found for " + qry)
            return None

        rows = re.findall(r'<tr>(.+?)</tr>', str(res['content']), re.DOTALL)

        if not rows:
            self.debug(f"No passive DNS results for {qry}")
            return None

        data = list()

        for row in rows:
            columns = re.findall(r'<td.*?>(.*?)</td>', row, re.DOTALL)

            # 0 seems to indicate no genuine issue
            if len(columns) == 0:
                continue

            if len(columns) != 7:
                self.error(f"Unexpected number of columns for row. Expected 7, Found {len(columns)}")
                continue

            data.append(columns)

        self.info(f"Retrieved {len(data)} DNS records for {qry}")

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if srcModuleName == self.__class__.__name__:
            self.debug(f"Ignoring {eventName}, from self.")
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        data = self.query(eventData)

        if data is None or len(data) == 0:
            self.info(f"No passive DNS data found for {eventData}")
            return

        domains = list()

        for record in data:
            if self.checkForStop():
                return

            if self.errorState:
                return

            # first_seen = record[0]
            # last_seen = record[1]
            query_html = record[2]
            answer_type = record[3]
            answer_html = record[4]
            # ttl = record[5]
            # count = record[6]

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
                    self.debug("Skipping invalid IP address " + answer)
                    continue

                if self.opts['verify'] and not self.sf.validateIP(query, answer):
                    self.debug(f"Host {query} no longer resolves to {answer}")
                    continue

                evt = SpiderFootEvent("IP_ADDRESS", answer, self.__name__, event)
                self.notifyListeners(evt)

            if answer_type == 'AAAA':
                if not self.getTarget().matches(query, includeChildren=True, includeParents=True):
                    continue

                if not self.sf.validIP6(answer):
                    self.debug(f"Skipping invalid IPv6 address {answer}")
                    continue

                if self.opts['verify'] and not self.sf.validateIP(query, answer):
                    self.debug(f"Host {query} no longer resolves to {answer}")
                    continue

                evt = SpiderFootEvent("IPV6_ADDRESS", answer, self.__name__, event)
                self.notifyListeners(evt)

        for domain in set(domains):
            if self.checkForStop():
                return

            if domain in self.results:
                continue

            if not self.getTarget().matches(domain, includeChildren=True, includeParents=True):
                continue

            if self.opts['verify'] and not self.sf.resolveHost(domain) and not self.sf.resolveHost6(domain):
                self.debug(f"Host {domain} could not be resolved")
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", domain, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("INTERNET_NAME", domain, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_open_passive_dns_database class
