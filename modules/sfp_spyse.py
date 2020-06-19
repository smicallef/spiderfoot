# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_spyse
# Purpose:     SpiderFoot plug-in to search Spyse API for IP address and
#              domain information.
#
# Authors:      <bcoles@gmail.com>, Krishnasis Mandal<krishnasis@hotmail.com>
#
# Created:     2020-02-22
# Updated:     2020-05-06
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.request, urllib.parse, urllib.error
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_spyse(SpiderFootPlugin):
    """Spyse:Footprint,Investigate,Passive:Passive DNS:apikey:SpiderFoot plug-in to search Spyse API for IP address and domain information."""

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
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
    }

    cohostcount = 0
    results = None
    errorState = False
    # The maximum number of records returned per offset from Sypse API
    limit = 100

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
        return ["IP_ADDRESS", "IPV6_ADDRESS", "DOMAIN_NAME", "INTERNET_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED", "DOMAIN_NAME",
                "IP_ADDRESS", "IPV6_ADDRESS", "CO_HOSTED_SITE", 
                "RAW_RIR_DATA", "TCP_PORT_OPEN", "OPERATING_SYSTEM",
                "WEBSERVER_BANNER", "WEBSERVER_HTTPHEADERS"]

    # Query Subdomains
    # https://spyse.com/tools/api#/domain/subdomain
    def querySubdomains(self, qry, currentOffset):
        params = {
            'domain': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'limit': self.limit, 
            'offset': currentOffset
        }
        headers = {
            'Accept' : "application/json",
            'Authorization' : "Bearer " + self.opts['api_key']
        }
        
        res = self.sf.fetchUrl(
          'https://api.spyse.com/v2/data/domain/subdomain?' + urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    # Query IP port lookup
    # https://spyse.com/tools/api#/ip/port_by_ip
    def queryIPPort(self, qry, currentOffset):
        params = {
            'ip': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'limit': self.limit, 
            'offset': currentOffset
        }
        headers = {
            'Accept' : "application/json",
            'Authorization' : "Bearer " + self.opts['api_key']
        }
        res = self.sf.fetchUrl(
          'https://api.spyse.com/v2/data/ip/port?' + urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    # Query domains on IP
    # https://spyse.com/tools/api#/ip/domain_by_ip
    def queryDomainsOnIP(self, qry, currentOffset):
        params = {
            'ip': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'limit': self.limit, 
            'offset': currentOffset
        }
        headers = {
            'Accept' : "application/json",
            'Authorization' : "Bearer " + self.opts['api_key']
        }
        res = self.sf.fetchUrl(
          'https://api.spyse.com/v2/data/ip/domain?' + urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    # Query domains using domain as MX server
    # https://spyse.com/apidocs#/Domain%20related%20information/get_domains_using_as_mx
    # Note: currently unused
    def queryDomainsAsMX(self, qry, page=1):
        params = {
            'ip': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'limit': self.limit, 
            'offset': currentOffset
        }

        headers = {
            'Accept' : "application/json",
            'Authorization' : "Bearer " + self.opts['api_key']
        }

        res = self.sf.fetchUrl(
          'https://api.spyse.com/v2/data/ip/mx?' + urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)


    # Query SSL Certificates
    # https://spyse.com/tools/api#/certificate/certificate
    # Note: currently unused
    def querySSLCertificates(self, qry, currentOffset):
        params = {
            'hash': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'limit': self.limit, 
            'offset': currentOffset
        }

        headers = {
            'Accept' : "application/json",
            'Authorization' : "Bearer " + self.opts['api_key']
        }
        
        res = self.sf.fetchUrl(
          'https://api.spyse.com/v2/data/cert?' + urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )
        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    # Parse API response
    # https://spyse.com/apidocs
    def parseAPIResponse(self, res):
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

    # Report extra data in the record
    def reportExtraData(self, record, event):
        
        operatingSystem = record.get('operation_system')
        if operatingSystem is not None:
            evt = SpiderFootEvent('OPERATING_SYSTEM', str(operatingSystem), self.__name__, event)
            self.notifyListeners(evt)
        
        webServer = record.get('product')
        if webServer is not None:
            evt = SpiderFootEvent('WEBSERVER_BANNER', str(webServer), self.__name__, event)
            self.notifyListeners(evt)

        httpHeaders = record.get('http_headers')
        if httpHeaders is not None:
            evt = SpiderFootEvent('WEBSERVER_HTTPHEADERS', str(httpHeaders), self.__name__, event)
            self.notifyListeners(evt)

    # Handle events sent to this module
    def handleEvent(self, event):
           
        if self.errorState:
            return None

        if self.opts['api_key'] == '':
            self.sf.error("Warning: You enabled sfp_spyse but did not set an API key! Only the first page of results will be returned.", False)
            self.errorState = True
            return None

        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        # Query cohosts
        if eventName in ["IP_ADDRESS", "IPV6_ADDRESS"]:
            cohosts = list()
            currentOffset = 0
            nextPageHasData = True

            while nextPageHasData:
                if self.checkForStop():
                    return None

                data = self.queryDomainsOnIP(eventData, currentOffset)
                if not data:
                    nextPageHasData = False
                    break

                data = data.get("data")
                if data is None:
                    self.sf.debug("No domains found on IP address " + eventData)
                    nextPageHasData = False
                    break
                else:
                    records = data.get('items')
                    if records:
                        for record in records:
                            domain = record.get('name')
                            if domain:
                                evt = SpiderFootEvent('RAW_RIR_DATA', str(record), self.__name__, event)
                                self.notifyListeners(evt)
                                
                                cohosts.append(domain)
                                self.reportExtraData(record, event)

                # Calculate if there are any records in the next offset (page)
                if len(records) < self.limit:
                    nextPageHasData = False
                currentOffset += self.limit

            for co in set(cohosts):

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

        # Query open ports for source IP Address
        if eventName in ["IP_ADDRESS", "IPV6_ADDRESS"]:
            ports = list()
            currentOffset = 0
            nextPageHasData = True

            while nextPageHasData:
                if self.checkForStop():
                    return None
                data = self.queryIPPort(eventData, currentOffset)
                if not data:
                    nextPageHasData = False
                    break

                data = data.get("data")

                if data is None:
                    self.sf.debug("No open ports found for IP " + eventData)
                    nextPageHasData = False
                    break
                else:
                    records = data.get('items')
                    if records:
                        for record in records:
                            port = record.get('port')
                            if port:
                                evt = SpiderFootEvent('RAW_RIR_DATA', str(record), self.__name__, event)
                                self.notifyListeners(evt)
                                
                                ports.append(str(eventData) + ":" + str(port))
                                self.reportExtraData(record, event)

                    # Calculate if there are any records in the next offset (page)
                    if len(records) < self.limit:
                        nextPageHasData = False
                    currentOffset += self.limit
                
                for port in ports:
                    if port in self.results:
                        continue
                    self.results[port] = True
                
                    evt = SpiderFootEvent('TCP_PORT_OPEN', str(port), self.__name__, event)
                    self.notifyListeners(evt)

        # Query subdomains  
        if eventName in ["DOMAIN_NAME", "INTERNET_NAME"]:
            currentOffset = 0
            nextPageHasData = True
            domains = list()

            while nextPageHasData:
                if self.checkForStop():
                    return None

                data = self.querySubdomains(eventData, currentOffset)
                if not data:
                    nextPageHasData = False
                    break

                data = data.get("data")
                if data is None:
                    self.sf.debug("No subdomains found for domain " + eventData)
                    nextPageHasData = False
                    break
                else:
                    records = data.get('items')
                    if records:
                        for record in records:
                            domain = record.get('name')
                            if domain:
                                evt = SpiderFootEvent('RAW_RIR_DATA', str(record), self.__name__, event)
                                self.notifyListeners(evt)

                                domains.append(domain)
                                self.reportExtraData(record, event)

                # Calculate if there are any records in the next offset (page)
                if len(records) < self.limit:
                    nextPageHasData = False
                currentOffset += self.limit

            for domain in set(domains):

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
            
        return None

# End of sfp_spyse class
