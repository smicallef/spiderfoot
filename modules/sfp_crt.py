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
import urllib.parse
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_crt(SpiderFootPlugin):
    """Certificate Transparency:Footprint,Investigate,Passive:Search Engines::Gather hostnames from historical certificates in crt.sh."""

    opts = {
        'verify': True,
    }

    optdescs = {
        'verify': 'Verify certificate subject alternative names resolve.'
    }

    results = None
    cert_ids = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cert_ids = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['DOMAIN_NAME', 'INTERNET_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SSL_CERTIFICATE_RAW", "RAW_RIR_DATA",
                'INTERNET_NAME', 'INTERNET_NAME_UNRESOLVED', 'DOMAIN_NAME',
                'AFFILIATE_INTERNET_NAME', 'AFFILIATE_INTERNET_NAME_UNRESOLVED',
                'AFFILIATE_DOMAIN_NAME']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        params = {
            'q': '%.' + str(eventData),
            'output': 'json'
        }

        res = self.sf.fetchUrl('https://crt.sh/?' + urllib.parse.urlencode(params),
                               timeout=30,
                               useragent=self.opts['_useragent'])

        if res['content'] is None:
            self.sf.info("No certificate transparency info found for " + eventData)
            return None

        try:
            data = json.loads(res['content'])
        except BaseException as e:
            self.sf.debug('Error processing JSON response: ' + str(e))
            return None

        if data is None or len(data) == 0:
            return None

        evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

        domains = list()
        fetch_certs = list()

        for cert_info in data:
            cert_id = cert_info.get('id')

            if cert_id:
                # Don't process the same cert twice
                if cert_id in self.cert_ids:
                    continue
                self.cert_ids[cert_id] = True

            fetch_certs.append(cert_id)

            domain = cert_info.get('name_value')
            if '\n' in domain:
                doms = domain.split("\n")
                for d in doms:
                    domains.append(d.replace("*.", ""))
            else:
                if domain and domain != eventData:
                    domains.append(domain.replace("*.", ""))

        if self.opts['verify'] and len(domains) > 0:
            self.sf.info("Resolving " + str(len(set(domains))) + " domains ...")

        for domain in set(domains):
            if domain in self.results:
                continue

            if not self.sf.validHost(domain, self.opts['_internettlds']):
                continue

            if self.getTarget().matches(domain, includeChildren=True, includeParents=True):
                evt_type = 'INTERNET_NAME'
            else:
                evt_type = 'AFFILIATE_INTERNET_NAME'

            if self.opts['verify'] and not self.sf.resolveHost(domain):
                self.sf.debug("Host " + domain + " could not be resolved")
                evt_type += '_UNRESOLVED'

            evt = SpiderFootEvent(evt_type, domain, self.__name__, event)
            self.notifyListeners(evt)

            if self.sf.isDomain(domain, self.opts['_internettlds']):
                if evt_type.startswith('AFFILIATE'):
                    evt = SpiderFootEvent('AFFILIATE_DOMAIN_NAME', domain, self.__name__, event)
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent('DOMAIN_NAME', domain, self.__name__, event)
                    self.notifyListeners(evt)

        for cert_id in fetch_certs:
            if self.checkForStop():
                return None

            params = {
                'd': str(cert_id)
            }

            res = self.sf.fetchUrl('https://crt.sh/?' + urllib.parse.urlencode(params),
                                   timeout=30,
                                   useragent=self.opts['_useragent'])

            if res['content'] is None:
                self.sf.info("Error retrieving certificate with ID " + str(cert_id))
                continue

            try:
                cert = self.sf.parseCert(str(res['content']))
            except BaseException as e:
                self.sf.info('Error parsing certificate: ' + str(e))
                continue

            evt = SpiderFootEvent("SSL_CERTIFICATE_RAW", cert['text'], self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_crt class
