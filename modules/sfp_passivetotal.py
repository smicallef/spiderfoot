# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_passivetotal
# Purpose:      Performs lookups against the PassiveTotal API
#
# Author:      Johan Nestaas <johan.nestaas@riskiq.net>
#
# Created:     04/14/2016
# Copyright:   (c) RiskIQ
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from netaddr import IPNetwork
from passivetotal.libs.ssl import SslRequest
from passivetotal.libs.dns import DnsRequest
from passivetotal.libs.enrichment import EnrichmentRequest
from passivetotal.libs.whois import WhoisRequest
from passivetotal.libs.attributes import AttributeRequest
from sflib import (
    # SpiderFoot,
    SpiderFootPlugin,
    SpiderFootEvent,
)

IP_TYPES = (
    'AFFILIATE_IPADDR', 'BLACKLISTED_IPADDR', 'BLACKLISTED_AFFILIATE_IPADDR',
    'DEFACED_IPADDR', 'DEFACED_AFFILIATE_IPADDR', 'IP_ADDRESS',
    'MALICIOUS_IPADDR', 'MALICIOUS_AFFILIATE_IPADDR',
)

NET_TYPES = (
    'BLACKLISTED_NETBLOCK', 'MALICIOUS_NETBLOCK',
)

NAME_TYPES = (
    'AFFILIATE_INTERNET_NAME', 'DEFACED_INTERNET_NAME',
    'DEFACED_AFFILIATE_INTERNET_NAME', 'DOMAIN_NAME', 'MALICIOUS_INTERNET_NAME',
)

URL_TYPES = (
    'LINKED_URL_EXTERNAL', 'LINKED_URL_INTERNAL', 'URL_WEB_FRAMEWORK',
    'URL_JAVA_APPLET', 'URL_STATIC', 'URL_PASSWORD', 'URL_UPLOAD',
    'URL_FORM_HISTORIC', 'URL_FLASH_HISTORIC', 'URL_FLASH', 'URL_FORM',
    'URL_JAVASCRIPT', 'URL_JAVASCRIPT_HISTORIC', 'URL_WEB_FRAMEWORK_HISTORIC',
    'URL_JAVA_APPLET_HISTORIC', 'URL_STATIC_HISTORIC', 'URL_PASSWORD_HISTORIC',
    'URL_UPLOAD_HISTORIC',
)

RE_URL_DOMAIN = re.compile(r'^https?://([^/]+)')

SSL_TYPES = (
    'SSL_CERTIFICATE_RAW', 'SSL_CERTIFICATE_ISSUED', 'SSL_CERTIFICATE_ISSUER',
    'SSL_CERTIFICATE_MISMATCH',
)


def get_ips(event):
    if event.eventType in IP_TYPES:
        return [event.data]
    if 'NETBLOCK' in event.eventType:
        net = IPNetwork(event.data)
        return [str(ip) for ip in net]
    return None


def get_hostname(event):
    if 'URL' in event.eventType:
        match = RE_URL_DOMAIN.match(event.data)
        if not match:
            raise RuntimeError('URL in eventType but data fails to match URL '
                               'regex: %s' % str(event.data))
        return match.group(1)
    if event.eventType in NAME_TYPES:
        return event.data
    return None


class PTClient(object):

    def __init__(self):
        try:
            self.clients = {
                'ssl': SslRequest.from_config(),
                'dns': DnsRequest.from_config(),
                'enrichment': EnrichmentRequest.from_config(),
                'whois': WhoisRequest.from_config(),
                'attribute': AttributeRequest.from_config(),
            }
        except Exception:
            self.clients = None

    def __getattr__(self, attr):
        if self.clients is None:
            raise AttributeError('No PassiveTotal clients available, please '
                                 'configure passivetotal by running `'
                                 'sudo pip install passivetotal` and by running'
                                 ' `pt-config setup`')
        for name, client in self.clients.items():
            if hasattr(client, attr):
                val = getattr(client, attr)
                if not callable(val):
                    continue
                return val
        raise AttributeError('No PassiveTotal client attribute: %s' % attr)


class sfp_passivetotal(SpiderFootPlugin):
    '''passivetotal:footprint:Performs lookups against the PassiveTotal API'''

    # Default options
    opts = {}

    # Option descriptions
    optdescs = {}

    # Target
    results = dict()

    def setup(self, sfc, userOpts=dict()):
        ''' Performs setup of the module '''
        self.sf = sfc
        self.results = dict()
        self.client = PTClient()
        if self.client is None:
            self.sf.error('No PassiveTotal clients available, please configure '
                          'passivetotal by running `sudo pip install '
                          'passivetotal` and by running `pt-config setup`')
        # Clear out options so data won't persist.
        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        '''
        The events this module is interested in for input, * being all events.

        Pay attention to IP addresses, SSL certs, domain names, etc.
        '''
        if self.client is None:
            return []
        return ['*']

    def producedEvents(self):
        '''
        The events this module produces, to help the end user in selecting
        modules.
        '''
        if self.client is None:
            return []
        return ['INTERNET_NAME', 'IP_ADDRESS', 'EMAILADDR',
                'SSL_CERTIFICATE_RAW']

    def handleIP(self, ip):
        pdns_response = self.client.get_passive_dns(query=ip)
        pdns_results = pdns_response.get('results', [])
        resolves = {record['resolve'] for record in pdns_results}
        for resolve in resolves:
            yield 'INTERNET_NAME', resolve
        ssl_response = self.client.get_ssl_certificate_history(query=ip)
        ssl_results = ssl_response.get('results', [])
        shas = {record['sha1'] for record in ssl_results}
        for sha in shas:
            yield 'SSL_CERTIFICATE_RAW', sha
        osint_response = self.client.get_osint(query=ip)
        osint_results = osint_response.get('results', [])
        in_report = set()
        for result in osint_results:
            in_report |= set(result.get('inReport', []))
        for inrep in in_report:
            if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', inrep):
                yield 'IP_ADDRESS', inrep
            else:
                yield 'INTERNET_NAME', inrep

    def handleName(self, name):
        pdns_response = self.client.get_passive_dns(query=name)
        pdns_results = pdns_response.get('results', [])
        resolves = {record['resolve'] for record in pdns_results}
        for resolve in resolves:
            yield 'INTERNET_NAME', resolve
        whois_response = self.client.get_whois_details(query=name) or {}
        for typ in ('admin', 'billing', 'registrant', 'tech'):
            if whois_response.get(typ, {}).get('email'):
                yield 'EMAILADDR', whois_response[typ]['email']
        if whois_response.get('contactEmail'):
            yield 'EMAILADDR', whois_response['contactEmail']
        osint_response = self.client.get_osint(query=name)
        osint_results = osint_response.get('results', [])
        in_report = set()
        for result in osint_results:
            in_report |= set(result.get('inReport', []))
        for inrep in in_report:
            if re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', inrep):
                yield 'IP_ADDRESS', inrep
            else:
                yield 'INTERNET_NAME', inrep

    def handleEvent(self, event):
        ''' Handle events sent to the module '''
        if self.client is None:
            return None
        srcModuleName = event.module
        strType = '%s::%s' % (event.eventType, event.data)
        self.sf.debug('Received event %s from %s' % (strType, srcModuleName))
        ips = get_ips(event)
        host = get_hostname(event)
        if ips:
            for ip in ips:
                self.sf.debug('Found IP %s from %s' % (ip, strType))
                for typ, data in self.handleIP(ip):
                    evt = SpiderFootEvent(typ, data, self.__name__,
                                          event.sourceEvent)
                    self.notifyListeners(evt)
        if host:
            self.sf.debug('Found name %s from %s' % (host, strType))
            for typ, data in self.handleName(host):
                evt = SpiderFootEvent(typ, data, self.__name__,
                                      event.sourceEvent)
                self.notifyListeners(evt)
        return None

# End of sfp_passivetotal class
