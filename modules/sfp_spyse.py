# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_spyse
# Purpose:     SpiderFoot plug-in to search Spyse API for IP address and
#              domain information.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2020-02-22
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_spyse(SpiderFootPlugin):
    """Spyse:Footprint,Investigate,Passive:Passive DNS::SpiderFoot plug-in to search Spyse API for IP address and domain information."""

    # Default options
    opts = {
        'api_key': '',
        'delay': 1,
        'verify': True,
        'cohostsamedomain': False,
        'maxcohost': 100
    }

    # Option descriptions
    optdescs = {
        'api_key': 'Spyse API key.',
        'delay': 'Delay between requests, in seconds.',
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting."
    }

    cohostcount = 0
    results = None
    errorState = False

    # Initialize module and module options
    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "IPV6_ADDRESS", "DOMAIN_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED", "DOMAIN_NAME",
                "IP_ADDRESS", "IPV6_ADDRESS",
                "CO_HOSTED_SITE", "RAW_RIR_DATA"]

    # Query Subdomains
    # https://spyse.com/apidocs#/Subdomains
    def querySubdomains(self, qry, page=1):
        params = {
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'api_token': self.opts['api_key'],
            'page': str(page),
        }
        res = self.sf.fetchUrl(
          'https://api.spyse.com/v1/subdomains?' + urllib.parse.urlencode(params),
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query IP port lookup
    # https://spyse.com/apidocs#/IP%20port%20lookup
    # Note: currently unused
    def queryIpPort(self, qry, page=1):
        params = {
            'q': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'api_token': self.opts['api_key'],
            'page': str(page),
        }
        res = self.sf.fetchUrl(
          'https://api.spyse.com/v1/ip-port-lookup?' + urllib.parse.urlencode(params),
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query domains on IP
    # https://spyse.com/apidocs#/Domain%20related%20information/get_domains_on_ip
    def queryDomainsOnIp(self, qry, page=1):
        params = {
            'ip': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'api_token': self.opts['api_key'],
            'page': str(page),
        }
        res = self.sf.fetchUrl(
          'https://api.spyse.com/v1/domains-on-ip?' + urllib.parse.urlencode(params),
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Query domains using domain as MX server
    # https://spyse.com/apidocs#/Domain%20related%20information/get_domains_using_as_mx
    # Note: currently unused
    def queryDomainsOnIp(self, qry, page=1):
        params = {
            'ip': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'api_token': self.opts['api_key'],
            'page': str(page),
        }
        res = self.sf.fetchUrl(
          'https://api.spyse.com/v1/domains-on-ip?' + urllib.parse.urlencode(params),
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)


    # Query SSL Certificates
    # https://spyse.com/apidocs#/SSL%20certificates
    # Note: currently unused
    def querySslCertificates(self, qry, page=1):
        params = {
            'q': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'api_token': self.opts['api_key'],
            'page': str(page),
        }
        res = self.sf.fetchUrl(
          'https://api.spyse.com/v1/ssl-certificates?' + urllib.parse.urlencode(params),
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseApiResponse(res)

    # Parse API response
    # https://spyse.com/apidocs
    def parseApiResponse(self, res):
        if res['code'] == '400':
            self.sf.error("Malformed request", False)
            return None

        if res['code'] == '402':
            self.sf.error("Request limit exceeded", False)
            self.errorState = True
            return None

        if res['code'] == '403':
            self.sf.error("Authentication failed", False)
            self.errorState = True
            return None

        # Future proofing - Spyse does not implement rate limiting
        if res['code'] == '429':
            self.sf.error("You are being rate-limited by Spyse", False)
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.sf.error("Failed to retrieve content from Spyse", False)
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

        if data.get('message'):
            self.sf.debug("Received error from Spyse: " + data.get('message'))

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if eventData in self.results:
            return None

        if self.opts['api_key'] == '':
            self.sf.error("Warning: You enabled sfp_spyse but did not set an API key! Only the first page of results will be returned.", False)

        self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventName in ["IP_ADDRESS", "IPV6_ADDRESS"]:
            cohosts = list()
            data = self.queryDomainsOnIp(eventData)

            if data is None:
                self.sf.debug("No domains found on IP address " + eventData)
            else:
                evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
                self.notifyListeners(evt)

                records = data.get('records')
                if records:
                    for record in records:
                        domain = record.get('domain')
                        if domain:
                            cohosts.append(domain)

            for co in set(cohosts):
                if self.checkForStop():
                    return None

                if self.errorState:
                    return None

                if co in self.results:
                    continue

                if self.opts['verify'] and not self.sf.validateIP(co, eventData):
                    self.sf.debug("Host " + co + " no longer resolves to " + eventData)
                    continue

                if not self.opts['cohostsamedomain']:
                    if self.getTarget().matches(co, includeParents=True):
                        evt = SpiderFootEvent('INTERNET_NAME', co, self.__name__, event)
                        self.notifyListeners(evt)
                        if self.sf.isDomain(co, self.opts['_internettlds']):
                            evt = SpiderFootEvent('DOMAIN_NAME', co, self.__name__, event)
                            self.notifyListeners(evt)
                        continue

                if self.cohostcount < self.opts['maxcohost']:
                    evt = SpiderFootEvent('CO_HOSTED_SITE', co, self.__name__, event)
                    self.notifyListeners(evt)
                    self.cohostcount += 1

        if eventName in ["DOMAIN_NAME"]:
            domains = list()
            data = self.querySubdomains(eventData)

            if data is None:
                self.sf.debug("No subdomains found for domain " + eventData)
            else:
                evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
                self.notifyListeners(evt)

                records = data.get('records')
                if records:
                    for record in records:
                        domain = record.get('domain')
                        if domain:
                            domains.append(domain)

            for domain in set(domains):
                if self.checkForStop():
                    break

                if self.errorState:
                    break

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

# End of sfp_spyse class
