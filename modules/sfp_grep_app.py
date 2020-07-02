# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_grep_app
# Purpose:     Searches grep.app API for domains, URLs and emails related to the
#              specified domain.
#
# Author:      <bcoles[at]gmail[.]com>
#
# Created:     2020-04-12
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import math
import time
import re
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_grep_app(SpiderFootPlugin):
    """grep.app:Footprint,Investigate,Passive:Search Engines::Search grep.app API for links and emails related to the specified domain."""

    # Default options
    opts = {
        'max_pages': 20,
        'dns_resolve': True,
    }

    # Option descriptions
    optdescs = {
        'max_pages': "Maximum number of pages of results to fetch.",
        'dns_resolve': "DNS resolve each identified domain."
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
        return ["EMAILADDR", "EMAILADDR_GENERIC", "DOMAIN_NAME", 
                "INTERNET_NAME", "RAW_RIR_DATA",
                "INTERNET_NAME_UNRESOLVED", "LINKED_URL_INTERNAL"]

    def query(self, qry, page):
        params = {
            'q': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'page': str(page)
        }

        res = self.sf.fetchUrl("https://grep.app/api/search?" + urllib.parse.urlencode(params),
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        time.sleep(1)

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug("Error processing JSON response: " + str(e))
            return None

        return data

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if srcModuleName == 'sfp_grep_app':
            self.sf.debug("Ignoring " + eventData + ", from self.")
            return None

        hosts = list()
        page = 1
        per_page = 10
        pages = self.opts['max_pages']
        while page <= pages:
            if self.checkForStop():
                return None

            if self.errorState:
                return None

            res = self.query(eventData, page)

            if res is None:
                return None

            facets = res.get('facets')

            if facets is None:
                return None

            count = facets.get('count')

            if count is None:
                return None

            last_page = math.ceil(count / per_page)

            if last_page is None:
                pages = 0

            if last_page < pages:
                pages = last_page

            self.sf.info("Parsing page " + str(page) + " of " + str(pages))
            page += 1

            hits = res.get('hits')

            if hits is None:
                return None

            data = hits.get('hits')

            if data is None:
                return None

            for result in data:
                if result is None:
                    continue

                evt = SpiderFootEvent("RAW_RIR_DATA", str(result), self.__name__, event)
                self.notifyListeners(evt)

                content = result.get('content')

                if content is None:
                    continue

                snippet = content.get('snippet')

                if snippet is None:
                    continue

                links = self.sf.extractUrls(snippet.replace('<mark>', '').replace('</mark>', ''))
                if links:
                    for link in links:
                        if link in self.results:
                            continue

                        host = self.sf.urlFQDN(link)

                        if not self.getTarget().matches(host, includeChildren=True, includeParents=True):
                            continue

                        hosts.append(host)

                        if not self.getTarget().matches(self.sf.urlFQDN(link), includeChildren=True, includeParents=True):
                            self.sf.debug("Skipped unrelated link: " + link)
                            continue

                        self.sf.debug('Found a link: ' + link)
                        evt = SpiderFootEvent('LINKED_URL_INTERNAL', link, self.__name__, event)
                        self.notifyListeners(evt)
                        self.results[link] = True

                emails = self.sf.parseEmails(snippet.replace('<mark>', '').replace('</mark>', ''))
                if emails:
                    for email in emails:
                        if email in self.results:
                            continue

                        mail_domain = email.lower().split('@')[1]
                        if not self.getTarget().matches(mail_domain, includeChildren=True, includeParents=True):
                            self.sf.debug("Skipped unrelated email address: " + email)
                            continue

                        self.sf.info("Found e-mail address: " + email)
                        if email.split("@")[0] in self.opts['_genericusers'].split(","):
                            evttype = "EMAILADDR_GENERIC"
                        else:
                            evttype = "EMAILADDR"

                        evt = SpiderFootEvent(evttype, email, self.__name__, event)
                        self.notifyListeners(evt)
                        self.results[email] = True

        for host in set(hosts):
            if self.checkForStop():
                return None

            if self.errorState:
                return None

            if self.opts['dns_resolve'] and not self.sf.resolveHost(host):
                self.sf.debug("Host " + host + " could not be resolved")
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, event)
                self.notifyListeners(evt)
                continue

            evt = SpiderFootEvent("INTERNET_NAME", host, self.__name__, event)
            self.notifyListeners(evt)
            if self.sf.isDomain(host, self.opts["_internettlds"]):
                evt = SpiderFootEvent("DOMAIN_NAME", host, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_grep_app class

