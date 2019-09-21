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
import M2Crypto
import socket
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
                'SSL_CERTIFICATE_EXPIRING', 'SSL_CERTIFICATE_RAW']

    # Query SSL Tools for DNS
    def queryDns(self, domain):
        postdata = 'url=' + domain
 
        res = self.sf.fetchUrl('http://www.ssltools.com/api/dns',
                               postData=postdata,
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
 
        res = self.sf.fetchUrl('http://www.ssltools.com/api/scan',
                               postData=postdata,
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
            m2cert = M2Crypto.X509.load_cert_string(str(dump).replace('\r', ''))
        except M2Crypto.X509.X509Error as e:
            self.sf.info('Error parsing certificate')
            return None

        evt = SpiderFootEvent('SSL_CERTIFICATE_RAW', m2cert.as_text().encode('raw_unicode_escape'), self.__name__, event)
        self.notifyListeners(evt)

        issued = self.getIssued(m2cert)

        if issued:
            evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUED', issued, self.__name__, event)
            self.notifyListeners(evt)

        issuer = self.getIssuer(m2cert)

        if issuer:
            evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUER', issuer, self.__name__, event)
            self.notifyListeners(evt)

        if eventName != 'IP_ADDRESS':
            self.checkHostMatch(m2cert, eventData, event)

        # extract certificate Subject Alternative Names
        domains = list()
        for san in self.getSubjectAltNames(m2cert):
            domains.append(san.replace('DNS:', '').replace('*.', ''))

        for domain in set(domains):
            if self.getTarget().matches(domain, includeChildren=True):
                evt_type = 'INTERNET_NAME'
            else:
                evt_type = 'AFFILIATE_DOMAIN'

            if self.opts['verify'] and not self.resolveHost(domain):
                self.sf.debug("Host " + san + " could not be resolved")
                evt_type += '_UNRESOLVED'

            evt = SpiderFootEvent(evt_type, domain, self.__name__, event)
            self.notifyListeners(evt)

        # check certificate expiry
        self.checkExpiry(m2cert, event)

    # Retrieve the entity to whom the certificate was issued
    def getIssued(self, cert):
        try:
            issued = cert.get_subject().as_text().encode('raw_unicode_escape')
        except BaseException as e:
            self.sf.error("Error processing certificate: " + str(e), False)
            return None

        return issued

    # Retrieve the certificate issuer
    def getIssuer(self, cert):
        try:
            issuer = cert.get_issuer().as_text().encode('raw_unicode_escape')
        except BaseException as e:
            self.sf.error("Error processing certificate: " + str(e), False)
            return None

        return issuer

    # Extract the Subject Alternative Names from the certificate subject
    def getSubjectAltNames(self, cert):
        names = list()

        try:
            sans = cert.get_ext('subjectAltName').get_value().encode('raw_unicode_escape')

            if sans is None:
                return None

            for san in sans.split(','):
                names.append(san.strip())
        except LookupError as e:
            self.sf.debug("No alternative name found in certificate.")
            return None
        except BaseException as e:
            self.sf.debug("Error parsing certificate:" + str(e))
            return None

        return names

    # Check if the hostname matches the name of the server
    def checkHostMatch(self, cert, fqdn, sevt):
        fqdn = fqdn.lower()
        hosts = list()

        # Extract the CN from the issued section
        issued = self.getIssued(cert)

        if not issued:
            return False

        if "cn=" + fqdn in issued.lower():
            hosts.append('dns:' + fqdn)

        # Extract subject alternative names
        for host in self.getSubjectAltNames(cert):
            hosts.append(host.lower())

        self.sf.debug("Checking for " + fqdn + " in certificate subject")
        fqdn_tld = ".".join(fqdn.split(".")[1:]).lower()

        for host in hosts:
            if host == "dns:" + fqdn:
                return True
            if host == "dns:*." + fqdn_tld:
                return True

        evt = SpiderFootEvent('SSL_CERTIFICATE_MISMATCH', ', '.join(hosts), self.__name__, sevt)
        self.notifyListeners(evt)

        return False

    # Check if the expiration date is in the future
    def checkExpiry(self, cert, sevt):
        try:
            exp = int(time.mktime(cert.get_not_after().get_datetime().timetuple()))
            expstr = cert.get_not_after().get_datetime().strftime("%Y-%m-%d %H:%M:%S")
            now = int(time.time())
            warnexp = now + self.opts['certexpiringdays'] * 86400
        except ValueError as e:
            self.sf.error("Error processing date in certificate.", False)
            return None

        if exp <= now:
            evt = SpiderFootEvent("SSL_CERTIFICATE_EXPIRED", expstr, self.__name__, sevt)
            self.notifyListeners(evt)
            return None

        if exp <= warnexp:
            evt = SpiderFootEvent("SSL_CERTIFICATE_EXPIRING", expstr, self.__name__, sevt)
            self.notifyListeners(evt)
            return None

# End of sfp_ssltools class
