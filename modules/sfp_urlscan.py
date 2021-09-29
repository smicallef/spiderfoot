# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_urlscan
# Purpose:     Search URLScan.io cache for domain information.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-09-09
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_urlscan(SpiderFootPlugin):

    meta = {
        'name': "URLScan.io",
        'summary': "Search URLScan.io cache for domain information.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://urlscan.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://urlscan.io/about-api/"
            ],
            'favIcon': "https://urlscan.io/img/urlscan_256.png",
            'logo': "https://urlscan.io/img/urlscan_256.png",
            'description': "urlscan.io is a service to scan and analyse websites. "
            "When a URL is submitted to urlscan.io, an automated process will browse to the URL "
            "like a regular user and record the activity that this page navigation creates. "
            "This includes the domains and IPs contacted, the resources (JavaScript, CSS, etc) requested from "
            "those domains, as well as additional information about the page itself. "
            "urlscan.io will take a screenshot of the page, record the DOM content, JavaScript global variables, "
            "cookies created by the page, and a myriad of other observations.",
        }
    }

    opts = {
        'verify': True
    }
    optdescs = {
        'verify': 'Verify that any hostnames found on the target domain still resolve?'
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
        return ['INTERNET_NAME']

    # What events this module produces
    def producedEvents(self):
        return ['GEOINFO', 'LINKED_URL_INTERNAL', 'RAW_RIR_DATA',
                'DOMAIN_NAME', 'INTERNET_NAME', 'INTERNET_NAME_UNRESOLVED',
                'BGP_AS_MEMBER', 'WEBSERVER_BANNER']

    # https://urlscan.io/about-api/
    def query(self, qry):
        params = {
            'q': 'domain:' + qry.encode('raw_unicode_escape').decode("ascii", errors='replace')
        }

        res = self.sf.fetchUrl('https://urlscan.io/api/v1/search/?' + urllib.parse.urlencode(params),
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        if res['code'] == "429":
            self.error("You are being rate-limited by URLScan.io.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.info("No results info found for " + qry)
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        data = self.query(eventData)

        if data is None:
            return

        results = data.get('results')

        if not results:
            return

        evt = SpiderFootEvent('RAW_RIR_DATA', str(results), self.__name__, event)
        self.notifyListeners(evt)

        urls = list()
        asns = list()
        domains = list()
        locations = list()
        servers = list()

        for res in results:
            page = res.get('page')

            if not page:
                continue

            domain = page.get('domain')

            if not domain:
                continue

            if not self.getTarget().matches(domain, includeParents=True):
                continue

            if domain.lower() != eventData.lower():
                domains.append(domain)

            asn = page.get('asn')

            if asn:
                asns.append(asn.replace('AS', ''))

            location = ', '.join([_f for _f in [page.get('city'), page.get('country')] if _f])

            if location:
                locations.append(location)

            server = page.get('server')

            if server:
                servers.append(server)

            task = res.get('task')

            if not task:
                continue

            url = task.get('url')

            if self.getTarget().matches(self.sf.urlFQDN(url), includeParents=True):
                urls.append(url)

        for url in set(urls):
            evt = SpiderFootEvent('LINKED_URL_INTERNAL', url, self.__name__, event)
            self.notifyListeners(evt)

        for location in set(locations):
            evt = SpiderFootEvent('GEOINFO', location, self.__name__, event)
            self.notifyListeners(evt)

        if self.opts['verify'] and len(domains) > 0:
            self.info("Resolving " + str(len(set(domains))) + " domains ...")

        for domain in set(domains):
            if self.opts['verify'] and not self.sf.resolveHost(domain) and not self.sf.resolveHost6(domain):
                evt = SpiderFootEvent('INTERNET_NAME_UNRESOLVED', domain, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent('INTERNET_NAME', domain, self.__name__, event)
                self.notifyListeners(evt)

            if self.sf.isDomain(domain, self.opts['_internettlds']):
                evt = SpiderFootEvent('DOMAIN_NAME', domain, self.__name__, event)
                self.notifyListeners(evt)

        for asn in set(asns):
            evt = SpiderFootEvent('BGP_AS_MEMBER', asn, self.__name__, event)
            self.notifyListeners(evt)

        for server in set(servers):
            evt = SpiderFootEvent('WEBSERVER_BANNER', server, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_ipinfo class
