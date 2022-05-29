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
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time
import urllib.parse

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_crt(SpiderFootPlugin):

    meta = {
        'name': "Certificate Transparency",
        'summary': "Gather hostnames from historical certificates in crt.sh.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://crt.sh/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://sectigo.com/",
                "https://github.com/crtsh"
            ],
            'favIcon': "https://crt.sh/sectigo_s.png",
            'logo': "https://crt.sh/sectigo_s.png",
            'description': "Free CT Log Certificate Search Tool from Sectigo (formerly Comodo CA)."
        }
    }

    opts = {
        'verify': True,
        'fetchcerts': True,
    }

    optdescs = {
        'verify': 'Verify certificate subject alternative names resolve.',
        'fetchcerts': 'Fetch each certificate found, for processing by other modules.',
    }

    results = None
    cert_ids = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.errorState = False
        self.results = self.tempStorage()
        self.cert_ids = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['DOMAIN_NAME', 'INTERNET_NAME']

    def producedEvents(self):
        return [
            "SSL_CERTIFICATE_RAW",
            "RAW_RIR_DATA",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "DOMAIN_NAME",
            "CO_HOSTED_SITE",
            "CO_HOSTED_SITE_DOMAIN"
        ]

    def queryDomain(self, qry: str):
        params = {
            'q': '%.' + qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'output': 'json'
        }

        res = self.sf.fetchUrl(
            "https://crt.sh/?" + urllib.parse.urlencode(params),
            timeout=30,
            useragent=self.opts['_useragent']
        )

        time.sleep(0.5)

        return self.parseApiResponse(res)

    def parseApiResponse(self, res: dict):
        if not res:
            self.error("No response from crt.sh")
            return None

        if res['code'] == '404':
            self.debug("No results for query")
            return None

        # Future proofing - crt.sh does not implement rate limiting
        if res['code'] == '429':
            self.error("You are being rate-limited by crt.sh")
            self.errorState = True
            return None

        if res['code'] == '500' or res['code'] == '502' or res['code'] == '503':
            self.error("crt.sh service is unavailable")
            self.errorState = True
            return None

        # Catch all other non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error("Failed to retrieve content from crt.sh")
            self.errorState = True
            return None

        if not res['content']:
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    def handleEvent(self, event):
        if self.errorState:
            return

        if event.data in self.results:
            return

        self.results[event.data] = True

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        data = self.queryDomain(event.data)

        if not data:
            self.debug(f"No certificate transparency results for domain {event.data}")
            return

        evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

        domains = list()
        certs = list()

        # Extract all domains and certificate IDs from each certificate
        for cert_info in data:
            cert_id = cert_info.get('id')

            if not cert_id:
                continue

            if cert_id in self.cert_ids:
                continue

            self.cert_ids[cert_id] = True

            if self.opts['fetchcerts']:
                certs.append(cert_id)

            domain = cert_info.get('name_value')

            if not domain:
                continue

            for d in domain.split("\n"):
                if d.lower() == event.data.lower():
                    continue
                domains.append(d.lower().replace("*.", ""))

        if self.opts['fetchcerts'] and len(certs) > 0:
            self.info(f"Retrieving {len(set(certs))} certificates ...")

        # Fetch and store each certificate
        # Report SAN domains for each certificate
        for cert_id in set(certs):
            if self.checkForStop():
                return

            if self.errorState:
                break

            params = {
                'd': str(cert_id)
            }

            res = self.sf.fetchUrl(
                'https://crt.sh/?' + urllib.parse.urlencode(params),
                timeout=30,
                useragent=self.opts['_useragent']
            )

            time.sleep(0.5)

            if not res or not res['content']:
                self.error(f"Error retrieving certificate with ID {cert_id}. No response from crt.sh")
                continue

            try:
                cert = self.sf.parseCert(str(res['content']))
            except Exception as e:
                self.info(f"Error parsing certificate: {e}")
                continue

            cert_text = cert.get('text')

            if cert_text:
                evt = SpiderFootEvent("SSL_CERTIFICATE_RAW", str(cert_text), self.__name__, event)
                self.notifyListeners(evt)

            sans = cert.get('altnames', list())

            if not sans:
                continue

            for san in sans:
                if san.lower() == event.data.lower():
                    continue
                domains.append(san.lower().replace("*.", ""))

        if self.opts['verify'] and len(domains) > 0:
            self.info(f"Resolving {len(set(domains))} domains ...")

        for domain in set(domains):
            if domain in self.results:
                continue

            if not self.sf.validHost(domain, self.opts['_internettlds']):
                continue

            if self.getTarget().matches(domain, includeChildren=True, includeParents=True):
                evt_type = 'INTERNET_NAME'
                if self.opts['verify'] and not self.sf.resolveHost(domain) and not self.sf.resolveHost6(domain):
                    self.debug(f"Host {domain} could not be resolved")
                    evt_type += '_UNRESOLVED'
            else:
                evt_type = 'CO_HOSTED_SITE'

            evt = SpiderFootEvent(evt_type, domain, self.__name__, event)
            self.notifyListeners(evt)

            if self.sf.isDomain(domain, self.opts['_internettlds']):
                if evt_type == 'CO_HOSTED_SITE':
                    evt = SpiderFootEvent('CO_HOSTED_SITE_DOMAIN', domain, self.__name__, event)
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent('DOMAIN_NAME', domain, self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_crt class
