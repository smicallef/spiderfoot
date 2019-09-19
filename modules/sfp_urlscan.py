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
import socket
import urllib
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_urlscan(SpiderFootPlugin):
    """URLScan.io:Footprint,Investigate,Passive:Search Engines::Search URLScan.io cache for domain information."""

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

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['INTERNET_NAME']

    # What events this module produces
    def producedEvents(self):
        return ['GEOINFO', 'LINKED_URL_INTERNAL', 'RAW_RIR_DATA',
                'INTERNET_NAME', 'INTERNET_NAME_UNRESOLVED', 'BGP_AS_MEMBER', 'WEBSERVER_BANNER']

    # Resolve a host
    def resolveHost(self, host):
        try:
            # IDNA-encode the hostname in case it contains unicode
            if type(host) != unicode:
                host = unicode(host, "utf-8", errors='replace').encode("idna")
            else:
                host = host.encode("idna")

            addrs = socket.gethostbyname_ex(host)
            if not addrs:
                return False

            return True
        except BaseException as e:
            self.sf.debug("Unable to resolve " + host + ": " + str(e))
            return False

    # https://urlscan.io/about-api/
    def query(self, qry):
        params = {
            'q': 'domain:' + qry.encode('raw_unicode_escape')
        }

        res = self.sf.fetchUrl('https://urlscan.io/api/v1/search/?' + urllib.urlencode(params),
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        if res['code'] == "429":
            self.sf.error("You are being rate-limited by URLScan.io.", False)
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.info("No results info found for " + qry)
            return None

        try:
            result = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        return result

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        self.results[eventData] = True

        data = self.query(eventData)

        if data is None:
            return None

        results = data.get('results')

        if not results:
            return None

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

            location = ', '.join(filter(None, [page.get('city'), page.get('country')]))

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

        for domain in set(domains):
            if self.opts['verify'] and not self.resolveHost(domain):
                evt = SpiderFootEvent('INTERNET_NAME_UNRESOLVED', domain, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent('INTERNET_NAME', domain, self.__name__, event)
                self.notifyListeners(evt)

        for asn in set(asns):
            evt = SpiderFootEvent('BGP_AS_MEMBER', asn, self.__name__, event)
            self.notifyListeners(evt)

        for server in set(servers):
            evt = SpiderFootEvent('WEBSERVER_BANNER', server, self.__name__, event)
            self.notifyListeners(evt)

        return None

# End of sfp_ipinfo class
