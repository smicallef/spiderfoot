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
import socks
import ssl
import time
import M2Crypto
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_sslcert(SpiderFootPlugin):
    """SSL Certificates:Footprint,Investigate:Crawling and Scanning::Gather information about SSL certificates used by the target's HTTPS sites."""


    # Default options
    opts = {
        "tryhttp": True,
        "ssltimeout": 10,
        "certexpiringdays": 30
    }

    # Option descriptions
    optdescs = {
        "tryhttp": "Also try to HTTPS-connect to HTTP sites and hostnames.",
        "ssltimeout": "Seconds before giving up trying to HTTPS connect.",
        "certexpiringdays": "Number of days in the future a certificate expires to consider it as expiring."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["INTERNET_NAME", "LINKED_URL_INTERNAL"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SSL_CERTIFICATE_ISSUED", "SSL_CERTIFICATE_ISSUER",
                "SSL_CERTIFICATE_MISMATCH", "SSL_CERTIFICATE_EXPIRED",
                "SSL_CERTIFICATE_EXPIRING", "SSL_CERTIFICATE_RAW"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventName == "LINKED_URL_INTERNAL":
            fqdn = self.sf.urlFQDN(eventData.lower())
        else:
            fqdn = eventData

        if fqdn not in self.results:
            self.results[fqdn] = True
        else:
            return None

        if not eventData.lower().startswith("https://") and not self.opts['tryhttp']:
            return None

        self.sf.debug("Testing SSL for: " + eventData)
        # Re-fetch the certificate from the site and process
        try:
            s = socket.socket()
            s.settimeout(int(self.opts['ssltimeout']))
            s.connect((fqdn, 443))
            sock = ssl.wrap_socket(s)
            sock.do_handshake()
            rawcert = sock.getpeercert(True)
            cert = ssl.DER_cert_to_PEM_cert(rawcert)
            m2cert = M2Crypto.X509.load_cert_string(str(cert).replace('\r', ''))
        except BaseException as x:
            self.sf.info("Unable to SSL-connect to " + fqdn)
            return None

        # Generate the event for the raw cert (in text form)
        # Cert raw data text contains a lot of gems..
        rawevt = SpiderFootEvent("SSL_CERTIFICATE_RAW", 
                                 m2cert.as_text().encode('raw_unicode_escape'), 
                                 self.__name__, event)
        self.notifyListeners(rawevt)

        # Generate events for other cert aspects
        self.getIssued(m2cert, event)
        self.getIssuer(m2cert, event)
        self.checkHostMatch(m2cert, fqdn, event)
        try:
            self.checkExpiry(m2cert, event)
        except M2Crypto.X509.X509Error as e:
            self.sf.error("Error processing certificate: " + str(e), False)

    # Report back who the certificate was issued to
    def getIssued(self, cert, sevt):
        issued = cert.get_subject().as_text().encode('raw_unicode_escape')
        evt = SpiderFootEvent("SSL_CERTIFICATE_ISSUED", issued, self.__name__, sevt)
        self.notifyListeners(evt)

    # Report back the certificate issuer
    def getIssuer(self, cert, sevt):
        issuer = cert.get_issuer().as_text().encode('raw_unicode_escape')
        evt = SpiderFootEvent("SSL_CERTIFICATE_ISSUER", issuer, self.__name__, sevt)
        self.notifyListeners(evt)

    # Check if the hostname matches the name of the server
    def checkHostMatch(self, cert, fqdn, sevt):
        fqdn = fqdn.lower()
        hosts = ""

        # Extract the CN from the issued section
        issued = cert.get_subject().as_text().encode('raw_unicode_escape')
        self.sf.debug("Checking for " + fqdn + " in " + issued.lower())
        if "cn=" + fqdn in issued.lower():
            hosts = 'dns:' + fqdn

        try:
            hosts = hosts + " " + cert.get_ext("subjectAltName").get_value().encode('raw_unicode_escape').lower()
        except LookupError as e:
            self.sf.debug("No alternative name found in certificate.")

        fqdn_tld = ".".join(fqdn.split(".")[1:]).lower()
        if "dns:" + fqdn not in hosts and "dns:*." + fqdn_tld not in hosts:
            evt = SpiderFootEvent("SSL_CERTIFICATE_MISMATCH", hosts, self.__name__, sevt)
            self.notifyListeners(evt)

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
