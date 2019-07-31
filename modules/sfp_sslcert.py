# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_sslcert
# Purpose:      Gather information about SSL certificates behind HTTPS sites.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     23/08/2013
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import socket
import ssl
import time
import M2Crypto
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_sslcert(SpiderFootPlugin):
    """SSL Certificates:Footprint,Investigate:Crawling and Scanning::Gather information about SSL certificates used by the target's HTTPS sites."""

    # Default options
    opts = {
        "tryhttp": True,
        'verify': True,
        "ssltimeout": 10,
        "certexpiringdays": 30
    }

    # Option descriptions
    optdescs = {
        "tryhttp": "Also try to HTTPS-connect to HTTP sites and hostnames.",
        'verify': "Verify certificate subject alternative names resolve.",
        "ssltimeout": "Seconds before giving up trying to HTTPS connect.",
        "certexpiringdays": "Number of days in the future a certificate expires to consider it as expiring."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["INTERNET_NAME", "LINKED_URL_INTERNAL", "IP_ADDRESS"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ['TCP_PORT_OPEN',
                'INTERNET_NAME', 'INTERNET_NAME_UNRESOLVED',
                'AFFILIATE_DOMAIN', 'AFFILIATE_DOMAIN_UNRESOLVED',
                "SSL_CERTIFICATE_ISSUED", "SSL_CERTIFICATE_ISSUER",
                "SSL_CERTIFICATE_MISMATCH", "SSL_CERTIFICATE_EXPIRED",
                "SSL_CERTIFICATE_EXPIRING", "SSL_CERTIFICATE_RAW"]

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

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventName == "LINKED_URL_INTERNAL":
            if not eventData.lower().startswith("https://") and not self.opts['tryhttp']:
                return None

            fqdn = self.sf.urlFQDN(eventData.lower())
        else:
            fqdn = eventData

        if fqdn not in self.results:
            self.results[fqdn] = True
        else:
            return None

        port = 443
        self.sf.debug("Testing SSL for: " + eventData + ':' + str(port))
        # Re-fetch the certificate from the site and process
        try:
            s = socket.socket()
            s.settimeout(int(self.opts['ssltimeout']))
            s.connect((fqdn, port))
            sock = ssl.wrap_socket(s)
            sock.do_handshake()
            rawcert = sock.getpeercert(True)
            cert = ssl.DER_cert_to_PEM_cert(rawcert)
            m2cert = M2Crypto.X509.load_cert_string(str(cert).replace('\r', ''))
        except BaseException as x:
            self.sf.info("Unable to SSL-connect to " + fqdn)
            return None

        if eventName in ['INTERNET_NAME', 'IP_ADDRESS']:
            evt = SpiderFootEvent('TCP_PORT_OPEN', eventData + ':' + str(port), self.__name__, event)
            self.notifyListeners(evt)

        # Generate the event for the raw cert (in text form)
        # Cert raw data text contains a lot of gems..
        rawevt = SpiderFootEvent("SSL_CERTIFICATE_RAW", 
                                 m2cert.as_text().encode('raw_unicode_escape'), 
                                 self.__name__, event)
        self.notifyListeners(rawevt)

        issued = self.getIssued(m2cert)

        if issued is not None:
            evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUED', issued, self.__name__, event)
            self.notifyListeners(evt)

        issuer = self.getIssuer(m2cert)

        if issuer is not None:
            evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUER', issuer, self.__name__, event)
            self.notifyListeners(evt)

        if eventName != "IP_ADDRESS":
            self.checkHostMatch(m2cert, fqdn, event)

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
        try:
            self.checkExpiry(m2cert, event)
        except M2Crypto.X509.X509Error as e:
            self.sf.error("Error processing certificate: " + str(e), False)

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
                return names

            for san in sans.split(','):
                names.append(san.strip())
        except LookupError as e:
            self.sf.debug("No alternative name found in certificate.")
        except BaseException as e:
            self.sf.debug("Error parsing certificate:" + str(e))

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
            self.sf.error("Couldn't process date in certificate.", False)
            return None

        if exp <= now:
            evt = SpiderFootEvent("SSL_CERTIFICATE_EXPIRED", expstr, self.__name__, sevt)
            self.notifyListeners(evt)
            return None

        if exp <= warnexp:
            evt = SpiderFootEvent("SSL_CERTIFICATE_EXPIRING", expstr, self.__name__, sevt)
            self.notifyListeners(evt)
            return None

# End of sfp_sslcert class
