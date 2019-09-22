# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_crt
# Purpose:      SpiderFoot plug-in to identify historical certificates for a domain
#               from crt.sh, and from this identify hostnames.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     17/03/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import M2Crypto
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_crt(SpiderFootPlugin):
    """Certificate Transparency:Footprint,Investigate,Passive:Search Engines::Gather hostnames from historical certificates in crt.sh."""


    # Default options
    opts = {}
    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['DOMAIN_NAME', 'INTERNET_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SSL_CERTIFICATE_ISSUED", "SSL_CERTIFICATE_ISSUER", "SSL_CERTIFICATE_RAW"]

    def getIssued(self, cert, sevt):
        issued = cert.get_subject().as_text().encode('raw_unicode_escape')
        evt = SpiderFootEvent("SSL_CERTIFICATE_ISSUED", issued, self.__name__, sevt)
        self.notifyListeners(evt)

    # Report back the certificate issuer
    def getIssuer(self, cert, sevt):
        issuer = cert.get_issuer().as_text().encode('raw_unicode_escape')
        evt = SpiderFootEvent("SSL_CERTIFICATE_ISSUER", issuer, self.__name__, sevt)
        self.notifyListeners(evt)

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        res = self.sf.fetchUrl("https://crt.sh/?CN=%25." + eventData + "&output=json",
                               timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
        if res['content'] is None:
            self.sf.info("No certificate transparency info found for " + eventData)
            return None

        if res['content'] == "[]":
            return None

        try:
            evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", res['content'], self.__name__, event)
            self.notifyListeners(evt)

            matches = re.findall("\"min_cert_id\":(\d+),", res['content'], re.IGNORECASE)
            for m in matches:
                if self.checkForStop():
                    return None
                dat = self.sf.fetchUrl("https://crt.sh/?d=" + m, timeout=self.opts['_fetchtimeout'], 
                                       useragent=self.opts['_useragent'])

                m2cert = M2Crypto.X509.load_cert_string(str(dat['content']).replace('\r', ''))
                rawevt = SpiderFootEvent("SSL_CERTIFICATE_RAW",
                                         m2cert.as_text().encode('raw_unicode_escape'),
                                         self.__name__, event)
                self.notifyListeners(rawevt)
                self.getIssuer(m2cert, evt)
                self.getIssued(m2cert, evt)
        except Exception as e:
            self.sf.debug("Error processing response: " + str(e))
            return None

        return None

# End of sfp_crt class
