# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_sslcert
# Purpose:      Gather information about SSL certificates behind HTTPS sites.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     23/08/2013
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

from urllib.parse import urlparse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin, SpiderFootHelpers

from modules.common_ssl_cert import process_ssl_cert_events

class sfp_sslcert(SpiderFootPlugin):

    meta = {
        'name': "SSL Certificate Analyzer",
        'summary': "Gather information about SSL certificates used by the target's HTTPS sites.",
        'flags': [],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"]
    }

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

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["INTERNET_NAME", "LINKED_URL_INTERNAL", "IP_ADDRESS"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ['TCP_PORT_OPEN', 'INTERNET_NAME', 'INTERNET_NAME_UNRESOLVED',
                'CO_HOSTED_SITE', 'CO_HOSTED_SITE_DOMAIN',
                "SSL_CERTIFICATE_ISSUED", "SSL_CERTIFICATE_ISSUER",
                "SSL_CERTIFICATE_MISMATCH", "SSL_CERTIFICATE_EXPIRED",
                "SSL_CERTIFICATE_EXPIRING", "SSL_CERTIFICATE_RAW",
                "DOMAIN_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName == "LINKED_URL_INTERNAL":
            if not eventData.lower().startswith("https://") and not self.opts['tryhttp']:
                return

            try:
                # Handle URLs containing port numbers
                u = urlparse(eventData)
                port = 443
                if u.port:
                    port = u.port
                fqdn = self.sf.urlFQDN(eventData.lower())
            except Exception:
                self.debug("Couldn't parse URL: " + eventData)
                return
        else:
            fqdn = eventData
            port = 443

        if fqdn not in self.results:
            self.results[fqdn] = True
        else:
            return

        self.debug("Testing SSL for: " + fqdn + ':' + str(port))
        # Re-fetch the certificate from the site and process
        try:
            sock = self.sf.safeSSLSocket(fqdn, port, self.opts['ssltimeout'])
            sock.do_handshake()
            dercert = sock.getpeercert(True)
            pemcert = SpiderFootHelpers.sslDerToPem(dercert)
            cert = self.sf.parseCert(str(pemcert), fqdn, self.opts['certexpiringdays'])
        except Exception as x:
            self.info("Unable to SSL-connect to " + fqdn + " (" + str(x) + ")")
            return

        if eventName in ['INTERNET_NAME', 'IP_ADDRESS']:
            evt = SpiderFootEvent('TCP_PORT_OPEN', fqdn + ':' + str(port), self.__name__, event)
            self.notifyListeners(evt)

        if not cert.get('text'):
            self.info("Failed to parse the SSL cert for " + fqdn)
            return

        # Generate the event for the raw cert (in text form)
        # Cert raw data text contains a lot of gems..
        rawevt = SpiderFootEvent("SSL_CERTIFICATE_RAW", cert['text'], self.__name__, event)
        self.notifyListeners(rawevt)

        process_ssl_cert_events(self, cert, event)

        

# End of sfp_sslcert class
