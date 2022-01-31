# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_certspotter
# Purpose:     Gather information about SSL certificates from SSLMate CertSpotter API.
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-08-15
# Copyright:   (c) bcoles
# Licence:     GPL
# -------------------------------------------------------------------------------

import base64
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_certspotter(SpiderFootPlugin):
    meta = {
        'name': "CertSpotter",
        'summary': "Gather information about SSL certificates from SSLMate CertSpotter API.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://sslmate.com/certspotter/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://sslmate.com/help/reference/ct_search_api_v1"
            ],
            'apiKeyInstructions': [
                "Visit https://sslmate.com/signup?for=ct_search_api",
                "Register a new account with an email",
                "Navigate to https://sslmate.com/account/",
                "The API key is listed under 'API Credentials'",
            ],
        }
    }

    # Default options
    opts = {
        'api_key': '',
        'verify': True,
        'max_pages': 20,
        'certexpiringdays': 30
    }

    # Option descriptions
    optdescs = {
        'api_key': 'CertSpotter API key.',
        'verify': "Verify certificate subject alternative names resolve.",
        'max_pages': "Maximum number of pages of results to fetch.",
        'certexpiringdays': 'Number of days in the future a certificate expires to consider it as expiring.'
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['DOMAIN_NAME']

    # What events this module produces
    def producedEvents(self):
        return [
            'INTERNET_NAME',
            'INTERNET_NAME_UNRESOLVED',
            'DOMAIN_NAME',
            'CO_HOSTED_SITE',
            'CO_HOSTED_SITE_DOMAIN',
            'SSL_CERTIFICATE_ISSUED',
            'SSL_CERTIFICATE_ISSUER',
            'SSL_CERTIFICATE_MISMATCH',
            'SSL_CERTIFICATE_EXPIRED',
            'SSL_CERTIFICATE_EXPIRING',
            'SSL_CERTIFICATE_RAW',
            'RAW_RIR_DATA'
        ]

    # Query CertSpotter issuances API endpoint
    def queryIssuances(self, domain, after=None):
        params = {
            'domain': domain.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'include_subdomains': 'true',
            'match_wildcards': 'true',
            'after': (after or '')
        }

        expand = '&expand='.join(['dns_names', 'issuer', 'cert'])

        headers = {
            'Accept': 'application/json',
            'Authorization': "Basic " + base64.b64encode(f"{self.opts['api_key']}:".encode('utf-8')).decode('utf-8')
        }

        res = self.sf.fetchUrl(
            f"https://api.certspotter.com/v1/issuances?{urllib.parse.urlencode(params)}&expand={expand}",
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent'],
        )

        # Free plan - 1,000 single-hostname queries / hour; 100 full-domain queries / hour
        time.sleep(1)

        if res['content'] is None:
            self.debug('No response from CertSpotter API')
            return None

        if res['code'] == '429':
            self.error("You are being rate-limited by CertSpotter")
            self.errorState = True
            return None

        if res['code'] != '200':
            self.error(f"Unexpected HTTP response code {res['code']} from CertSpotter")
            self.errorState = True
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        if self.errorState:
            return

        if self.opts['api_key'] == "":
            self.error(f"You enabled {self.__class__.__name__} but did not set an API key!")
            self.errorState = True
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        max_pages = int(self.opts['max_pages'])
        page = 1
        last_id = None
        hosts = list()
        while page <= max_pages:
            if self.checkForStop():
                break

            if self.errorState:
                break

            data = self.queryIssuances(eventData, last_id)

            if data is None or len(data) == 0:
                break

            page += 1

            evt = SpiderFootEvent('RAW_RIR_DATA', str(data), self.__name__, event)
            self.notifyListeners(evt)

            for result in data:
                cert_hosts = result.get('dns_names')

                if cert_hosts:
                    for d in cert_hosts:
                        if d != eventData:
                            hosts.append(d.replace("*.", ""))

                if result.get('cert') is None:
                    self.debug('Response data contains no certificate data')
                    continue

                try:
                    rawcert = "-----BEGIN CERTIFICATE-----\n"
                    rawcert += result.get('cert').get('data')
                    rawcert += "\n-----END CERTIFICATE-----\n"
                    cert = self.sf.parseCert(rawcert, eventData, self.opts['certexpiringdays'])
                except Exception as e:
                    self.info(f"Error parsing certificate: {e}")
                    continue

                if not cert.get('text'):
                    self.info("Failed to parse the SSL certificate")
                    continue

                evt = SpiderFootEvent('SSL_CERTIFICATE_RAW', cert['text'], self.__name__, event)
                self.notifyListeners(evt)

                if cert.get('issuer'):
                    evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUER', cert['issuer'], self.__name__, event)
                    self.notifyListeners(evt)

                if cert.get('issued'):
                    evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUED', cert['issued'], self.__name__, event)
                    self.notifyListeners(evt)

                for san in set(cert.get('altnames', list())):
                    hosts.append(san.replace("*.", ""))

                if cert.get('expired'):
                    evt = SpiderFootEvent("SSL_CERTIFICATE_EXPIRED", cert.get('expirystr', 'Unknown'), self.__name__, event)
                    self.notifyListeners(evt)
                    continue

                if cert.get('expiring'):
                    evt = SpiderFootEvent("SSL_CERTIFICATE_EXPIRING", cert.get('expirystr', 'Unknown'), self.__name__, event)
                    self.notifyListeners(evt)
                    continue

            # "To retrieve additional issuances, take the id field of the last issuance and pass it to the issuances endpoint in the after parameter"
            last_id = data[-1].get('id')

            if last_id is None:
                break

        if not hosts:
            return

        if self.opts['verify']:
            self.info(f"Resolving {len(set(hosts))} hostnames ...")

        for domain in set(hosts):
            if self.checkForStop():
                return

            if domain in self.results:
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

# End of sfp_certspotter class
