# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_ssltools
# Purpose:     Gather information about SSL certificates from SSLTools.com.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-06-05
# Copyright:   (c) bcoles
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_ssltools(SpiderFootPlugin):
    """SSL Tools:Footprint,Investigate,Passive:Crawling and Scanning::Gather information about SSL certificates from SSLTools.com."""

    # Default options
    opts = {
        'verify': True,
        'certexpiringdays': 30
    }

    # Option descriptions
    optdescs = {
        'verify': "Verify certificate subject alternative names resolve.",
        'certexpiringdays': 'Number of days in the future a certificate expires to consider it as expiring.'
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.__dataSource__ = 'SSL Tools'
        self.results = self.tempStorage()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['INTERNET_NAME', 'IP_ADDRESS']

    # What events this module produces
    def producedEvents(self):
        return ['IP_ADDRESS', 'TCP_PORT_OPEN', 'WEBSERVER_BANNER',
                'INTERNET_NAME', 'INTERNET_NAME_UNRESOLVED',
                'AFFILIATE_DOMAIN', 'AFFILIATE_DOMAIN_UNRESOLVED',
                'SSL_CERTIFICATE_ISSUED', 'SSL_CERTIFICATE_ISSUER',
                'SSL_CERTIFICATE_MISMATCH', 'SSL_CERTIFICATE_EXPIRED',
                'SSL_CERTIFICATE_EXPIRING', 'SSL_CERTIFICATE_RAW',
                'DOMAIN_NAME']

    # Query SSL Tools for DNS
    def queryDns(self, domain):
        postdata = 'url=' + domain
        hdr = { 'Content-type': 'application/x-www-form-urlencoded' }
 
        res = self.sf.fetchUrl('http://www.ssltools.com/api/dns',
                               postData=postdata,
                               headers=hdr,
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.sf.debug('No response from SSLTools.com')
            return None

        try:
            data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug('Error processing JSON response: ' + str(e))
            return None

        return data

    # Query SSL Tools for certificate information
    def queryScan(self, domain, port):
        postdata = 'url=' + domain + '&path=/&port=' + str(port) + '&live_scan=true'
        hdr = { 'Content-type': 'application/x-www-form-urlencoded' }
 
        res = self.sf.fetchUrl('http://www.ssltools.com/api/scan',
                               postData=postdata,
                               headers=hdr,
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        time.sleep(1)

        if res['content'] is None:
            self.sf.debug('No response from SSLTools.com')
            return None

        try:
            data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug('Error processing JSON response: ' + str(e))
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

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        data = self.queryDns(eventData)

        if data is None:
            self.sf.debug('No DNS information found for ' + eventData)
            return None

        addresses = data.get('addresses')

        for address in addresses:
            if self.sf.validIP(address):
                evt = SpiderFootEvent('IP_ADDRESS', address, self.__name__, event)
                self.notifyListeners(evt)

        port = 443
        data = self.queryScan(eventData, port)

        if data is None:
            self.sf.debug('No certificate information found for ' + eventData + ':' + str(port))
            return None

        response = data.get('response')

        if response is None or len(response) == 0:
            self.sf.debug('No certificate information found for ' + eventData + ':' + str(port))
            return None

        evt = SpiderFootEvent('RAW_RIR_DATA', str(response), self.__name__, event)
        self.notifyListeners(evt)

        evt = SpiderFootEvent('TCP_PORT_OPEN', eventData + ':' + str(port), self.__name__, event)
        self.notifyListeners(evt)

        banner = response.get('server')

        if banner:
            evt = SpiderFootEvent('WEBSERVER_BANNER', str(banner), self.__name__, event)
            self.notifyListeners(evt)

        try:
            dump = response.get('dump')
            cert = self.sf.parseCert(str(dump), eventData, self.opts['certexpiringdays'])
        except BaseException as e:
            self.sf.info('Error parsing certificate: ' + str(e))
            return None

        if not cert.get('text'):
            self.sf.info("Failed to parse the SSL cert for " + fqdn)
            return None

        evt = SpiderFootEvent('SSL_CERTIFICATE_RAW', cert['text'], self.__name__, event)
        self.notifyListeners(evt)

        if cert.get('issued'):
            evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUED', cert['issued'], self.__name__, event)
            self.notifyListeners(evt)

        if cert.get('issuer'):
            evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUER', cert['issuer'], self.__name__, event)
            self.notifyListeners(evt)

        if eventName != "IP_ADDRESS" and cert.get('mismatch'):
            evt = SpiderFootEvent('SSL_CERTIFICATE_MISMATCH', ', '.join(cert.get('hosts')), self.__name__, event)
            self.notifyListeners(evt)

        for san in set(cert.get('altnames', list())):
            if "*." in san:
                dom = san.replace("*.", ".")
            else:
                dom = san 

            if self.getTarget().matches(dom, includeChildren=True):
                evt_type = 'INTERNET_NAME'
            else:
                evt_type = 'AFFILIATE_DOMAIN'

            if self.opts['verify'] and not self.sf.resolveHost(dom):
                    self.sf.debug("Host " + dom + " could not be resolved")
                    evt_type += '_UNRESOLVED'

            if "*." not in san:
                evt = SpiderFootEvent(evt_type, san, self.__name__, event)
                self.notifyListeners(evt)
                if not evt_type.startswith('AFFILIATE') and self.sf.isDomain(san, self.opts['_internettlds']):
                    evt = SpiderFootEvent('DOMAIN_NAME', san, self.__name__, event)
                    self.notifyListeners(evt)

        if cert.get('expired'):
            evt = SpiderFootEvent("SSL_CERTIFICATE_EXPIRED", cert.get('expirystr', 'Unknown'), self.__name__, event)
            self.notifyListeners(evt)
            return None

        if cert.get('expiring'):
            evt = SpiderFootEvent("SSL_CERTIFICATE_EXPIRING", cert.get('expirystr', 'Unknown'), self.__name__, event)
            self.notifyListeners(evt)
            return None


# End of sfp_ssltools class
