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

import json
import urllib
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_crt(SpiderFootPlugin):
    """Certificate Transparency:Footprint,Investigate,Passive:Search Engines::Gather hostnames from historical certificates in crt.sh."""

    opts = {}
    optdescs = {}

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['DOMAIN_NAME', 'INTERNET_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SSL_CERTIFICATE_RAW"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        params = {
            'CN': '%.' + eventData.encode('raw_unicode_escape'),
            'output': 'json'
        }

        res = self.sf.fetchUrl('https://crt.sh/?' + urllib.urlencode(params),
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'])

        if res['content'] is None or res['content'] == "[]":
            self.sf.info("No certificate transparency info found for " + eventData)
            return None

        try:
            data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug('Error processing JSON response: ' + str(e))
            return None

        evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", str(data), self.__name__, event)
        self.notifyListeners(evt)

        cert_ids = list()

        for cert_info in data:
            cert_id = cert_info.get('min_cert_id')
            if cert_id:
                cert_ids.append(cert_id)

        for cert_id in set(cert_ids):
            if self.checkForStop():
                return None

            params = {
                'd': str(cert_id)
            }

            res = self.sf.fetchUrl('https://crt.sh/?' + urllib.urlencode(params),
                                   timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])

            try:
                cert = self.sf.parseCert(str(res['content']))
            except BaseException as e:
                self.sf.info('Error parsing certificate: ' + str(e))
                continue

            evt = SpiderFootEvent("SSL_CERTIFICATE_RAW", cert['text'], self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_crt class
