# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_spyse
# Purpose:     SpiderFoot plug-in to search Spyse API for IP address and
#              domain information.
#
# Authors:      <bcoles@gmail.com>, Krishnasis Mandal<krishnasis@hotmail.com>
#
# Created:     2020-02-22
# Updated:     2020-05-06
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_spyse(SpiderFootPlugin):
    meta = {
        'name': "Spyse",
        'summary': "Search Spyse.com Internet assets registry for information about domains, IPv4 hosts, potential vulnerabilities, passive DNS, etc.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://spyse.com",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://spyse.com/api"
            ],
            'apiKeyInstructions': [
                "Visit https://spyse.com",
                "Register a free account",
                "Navigate to https://spyse.com/user",
                "The API key is listed under 'API token'"
            ],
            'favIcon': "https://spyse.com/favicon/favicon-32x32.png",
            'logo': "https://spyse.com/favicon/favicon-32x32.png",
            'description': "Spyse is a platform that collects, analyzes, and delivers data about devices and websites "
                           "available on the Internet. It regularly probes every public IP address, crawls every "
                           "website, curates and enriches the resulting data, and makes it intelligible through an "
                           "interactive search engine and API.\n"
                           "Supported data models: IPv4 hosts, open ports, WHOIS, domains, websites, passive DNS, "
                           "potential vulnerabilities, autonomous systems, technologies, subnets, emails, IP "
                           "reputation, organization, etc."

        }
    }

    # Default options
    opts = {
        'api_key': '',
        'delay': 1,
        'verify': True,
        'cohostsamedomain': False,
        'maxcohost': 100
    }

    # Option descriptions
    optdescs = {
        'api_key': 'Spyse API key.',
        'delay': 'Delay between requests, in seconds.',
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
    }

    cohostcount = 0
    results = None
    errorState = False
    # The maximum number of records returned per offset from Sypse API
    limit = 100

    # Initialize module and module options
    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "DOMAIN_NAME", "INTERNET_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED", "DOMAIN_NAME",
                "IP_ADDRESS", "IPV6_ADDRESS", "CO_HOSTED_SITE",
                "RAW_RIR_DATA", "TCP_PORT_OPEN", "OPERATING_SYSTEM",
                "WEBSERVER_BANNER", "WEBSERVER_HTTPHEADERS",
                "COMPANY_NAME", "WEBSERVER_TECHNOLOGY", "PROVIDER_MAIL",
                "PROVIDER_DNS", "DNS_TEXT", "DNS_SPF", "COUNTRY_NAME",
                "WEB_ANALYTICS_ID", "VULNERABILITY", "SSL_CERTIFICATE_ISSUED",
                "SSL_CERTIFICATE_ISSUER" "EMAILADDR", "DOMAIN_REGISTRAR",
                "HTTP_CODE"]

    def querySubdomains(self, qry, currentOffset):
        """Query subdomains of domain

        https://spyse-dev.readme.io/reference/domains#domain_search

        Args:
            qry (str): domain name
            currentOffset (int): start from this search result offset

        Returns:
            dict: JSON formatted results
        """

        headers = {
            'Accept': "application/json",
            'Content-Type': "application/json",
            'Authorization': "Bearer " + self.opts['api_key']
        }
        body = {
            "search_params": [
                {
                    "name": {
                        "operator": "ends",
                        "value": f".{qry.encode('raw_unicode_escape').decode('ascii', errors='replace')}"
                    }
                }
            ],
            "limit": self.limit,
            "offset": currentOffset
        }

        res = self.sf.fetchUrl(
            'https://api.spyse.com/v4/data/domain/search',
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent'],
            postData=json.dumps(body)
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def queryDomainDetails(self, qry):
        """Query domain details

        https://spyse-dev.readme.io/reference/domains#domain_details

        Args:
            qry (str): Domain name

        Returns:
            dict: JSON formatted results
        """

        headers = {
            'Accept': "application/json",
            'Authorization': "Bearer " + self.opts['api_key']
        }
        res = self.sf.fetchUrl(
            f'https://api.spyse.com/v4/data/domain/{qry.encode("raw_unicode_escape").decode("ascii", errors="replace")}',
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def queryIPPort(self, qry):
        """Query IP port lookup

        https://spyse-dev.readme.io/reference/ips#ip_details

        Args:
            qry (str): IP address

        Returns:
            dict: JSON formatted results
        """

        headers = {
            'Accept': "application/json",
            'Authorization': "Bearer " + self.opts['api_key']
        }
        res = self.sf.fetchUrl(
            f'https://api.spyse.com/v4/data/ip/{qry.encode("raw_unicode_escape").decode("ascii", errors="replace")}',
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def queryDomainsOnIP(self, qry, currentOffset):
        """Query domains on IP

        https://spyse-dev.readme.io/reference/domains#domain_search

        Args:
            qry (str): IP address
            currentOffset (int): start from this search result offset

        Returns:
            dict: JSON formatted results
        """

        headers = {
            'Accept': "application/json",
            'Content-Type': "application/json",
            'Authorization': "Bearer " + self.opts['api_key']
        }
        body = {
            "search_params": [
                {
                    "dns_a": {
                        "operator": "eq",
                        "value": f"{qry.encode('raw_unicode_escape').decode('ascii', errors='replace')}"
                    }
                }
            ],
            "limit": self.limit,
            "offset": currentOffset
        }
        res = self.sf.fetchUrl(
            'https://api.spyse.com/v4/data/domain/search',
            postData=json.dumps(body),
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def parseAPIResponse(self, res):
        """Parse API response

        https://spyse-dev.readme.io/reference/quick-start

        Args:
            res: TBD

        Returns:
            dict: JSON formatted results
        """

        if res['code'] == '400':
            self.sf.error("Malformed request")
            return None

        if res['code'] == '402':
            self.sf.error("Request limit exceeded")
            self.errorState = True
            return None

        if res['code'] == '403':
            self.sf.error("Authentication failed")
            self.errorState = True
            return None

        # Future proofing - Spyse does not implement rate limiting
        if res['code'] == '429':
            self.sf.error("You are being rate-limited by Spyse")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.sf.error("Failed to retrieve content from Spyse")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.debug(f"Error processing JSON response: {e}")
            return None

        if data.get('message'):
            self.sf.debug("Received error from Spyse: " + data.get('message'))

        return data

    # Report extra data in the record
    def reportExtraData(self, record, event):
        # Note: 'operation_system' is the correct key (not 'operating_system')
        operatingSystem = record.get('operation_system')
        if operatingSystem:
            evt = SpiderFootEvent('OPERATING_SYSTEM', operatingSystem, self.__name__, event)
            self.notifyListeners(evt)

        webServer = record.get('product')
        if webServer:
            evt = SpiderFootEvent('WEBSERVER_BANNER', webServer, self.__name__, event)
            self.notifyListeners(evt)

        httpHeaders = record.get('http_headers')
        if httpHeaders:
            evt = SpiderFootEvent('WEBSERVER_HTTPHEADERS', httpHeaders, self.__name__, event)
            self.notifyListeners(evt)

    # Handle events sent to this module
    def handleEvent(self, event):

        if self.errorState:
            return

        if self.opts['api_key'] == '':
            self.sf.error("You enabled sfp_spyse but did not set an API key!")
            self.errorState = True
            return
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Query open ports for source IP Address
        if eventName in ["IP_ADDRESS"]:
            if self.checkForStop():
                return
            self.process_ip_event(event)

        # Query subdomains
        if eventName in ["DOMAIN_NAME", "INTERNET_NAME"]:
            if self.checkForStop():
                return
            self.process_domain_event(event)

    def process_ip_event(self, event):
        cohosts = list()
        currentOffset = 0
        nextPageHasData = True
        eventData = event.data

        while nextPageHasData:
            if self.checkForStop():
                return

            data = self.queryDomainsOnIP(eventData, currentOffset)
            if not data:
                nextPageHasData = False
                break

            data = data.get("data")
            if data is None:
                self.sf.debug("No domains found on IP address " + eventData)
                nextPageHasData = False
                break
            else:
                records = data.get('items')
                if records:
                    for record in records:
                        domain = record.get('name')
                        if domain:
                            evt = SpiderFootEvent('RAW_RIR_DATA', str(record), self.__name__, event)
                            self.notifyListeners(evt)

                            cohosts.append(domain)
                            self.reportExtraData(record, event)

            # Calculate if there are any records in the next offset (page)
            if len(records) < self.limit:
                nextPageHasData = False
            currentOffset += self.limit

        for co in set(cohosts):

            if co in self.results:
                continue

            if self.opts['verify'] and not self.sf.validateIP(co, eventData):
                self.sf.debug("Host " + co + " no longer resolves to " + eventData)
                continue

            if not self.opts['cohostsamedomain']:
                if self.getTarget().matches(co, includeParents=True):
                    evt = SpiderFootEvent('INTERNET_NAME', co, self.__name__, event)
                    self.notifyListeners(evt)
                    if self.sf.isDomain(co, self.opts['_internettlds']):
                        evt = SpiderFootEvent('DOMAIN_NAME', co, self.__name__, event)
                        self.notifyListeners(evt)
                    continue

            if self.cohostcount < self.opts['maxcohost']:
                evt = SpiderFootEvent('CO_HOSTED_SITE', co, self.__name__, event)
                self.notifyListeners(evt)
                self.cohostcount += 1

        ports = list()

        data = self.queryIPPort(eventData)
        if data:
            data = data.get("data")

            if data is None:
                self.sf.debug("No open ports found for IP " + eventData)
            else:
                records = data.get('items')
                if records:

                    for record in records:
                        if record.get("ports"):

                            for port_data in record["ports"]:

                                port = port_data.get('port')
                                if port:
                                    evt = SpiderFootEvent('RAW_RIR_DATA', str(record), self.__name__, event)
                                    self.notifyListeners(evt)

                                    ports.append(str(eventData) + ":" + str(port))
                                    self.reportExtraData(record, event)
                        if record.get("geo_info"):
                            country = record["geo_info"].get("country")
                            if country:
                                evt = SpiderFootEvent('COUNTRY_NAME', country, self.__name__, event)
                                self.notifyListeners(evt)
                        if record.get("cve_list"):
                            for cve in record["cve_list"]:
                                evt = SpiderFootEvent('VULNERABILITY', cve["id"], self.__name__, event)
                                self.notifyListeners(evt)
                        if record.get("technologies"):
                            for tech in record["technologies"]:
                                if tech.get("version"):
                                    evt = SpiderFootEvent('WEBSERVER_TECHNOLOGY',
                                                          f"{tech['name']} {tech['version']}",
                                                          self.__name__, event)
                                else:
                                    evt = SpiderFootEvent('WEBSERVER_TECHNOLOGY', tech['name'], self.__name__,
                                                          event)
                                self.notifyListeners(evt)

            for port in ports:
                if port in self.results:
                    continue
                self.results[port] = True

                evt = SpiderFootEvent('TCP_PORT_OPEN', str(port), self.__name__, event)
                self.notifyListeners(evt)

    def process_domain_event(self, event):
        currentOffset = 0
        nextPageHasData = True
        domains = list()
        eventData = event.data
        if event.module == "sfp_spyse" and (self.getTarget().targetValue in event.data):
            return

        domain_details = self.queryDomainDetails(eventData)
        if domain_details:
            domain_details_data = domain_details.get("data", {}).get("items", [])
            if len(domain_details_data) > 0:
                domain_item = domain_details_data[0]
                if domain_item.get("organizations"):
                    for org in domain_item.get("organizations", []):
                        if org.get("crunchbase"):
                            if org.get("crunchbase").get("is_primary", False):
                                org_name = org["crunchbase"].get("legal_name")
                                if not org_name:
                                    org_name = org["crunchbase"].get("name")
                                if org_name:
                                    evt = SpiderFootEvent('COMPANY_NAME', org_name, self.__name__, event)
                                    self.notifyListeners(evt)

                domain_dns = domain_item.get("dns_records")
                if domain_dns:
                    domain_dns_a_records = domain_dns.get("A")
                    if domain_dns_a_records:
                        for dns_A in domain_dns_a_records:
                            evt = SpiderFootEvent('IP_ADDRESS', dns_A, self.__name__, event)
                            self.notifyListeners(evt)

                    domain_dns_aaaa_records = domain_dns.get("AAAA")
                    if domain_dns_aaaa_records:
                        for dns_AAAA in domain_dns_aaaa_records:
                            evt = SpiderFootEvent('IPV6_ADDRESS', dns_AAAA, self.__name__, event)
                            self.notifyListeners(evt)

                    domain_dns_spf_records = domain_dns.get("SPF")
                    if domain_dns_spf_records:
                        for dns_spf in domain_dns_spf_records:
                            if dns_spf.get("raw"):
                                evt = SpiderFootEvent('DNS_SPF', dns_spf["raw"], self.__name__, event)
                                self.notifyListeners(evt)

                    domain_dns_txt_records = domain_dns.get("TXT")
                    if domain_dns_txt_records:
                        for dns_txt in domain_dns_txt_records:
                            evt = SpiderFootEvent('DNS_TEXT', dns_txt, self.__name__, event)
                            self.notifyListeners(evt)

                    domain_dns_ns_records = domain_dns.get("NS")
                    if domain_dns_ns_records:
                        for dns_ns in domain_dns_ns_records:
                            evt = SpiderFootEvent('PROVIDER_DNS', dns_ns, self.__name__, event)
                            self.notifyListeners(evt)

                    domain_dns_mx_records = domain_dns.get("MX")
                    if domain_dns_mx_records:
                        for dns_mx in domain_dns_mx_records:
                            evt = SpiderFootEvent('PROVIDER_MAIL', dns_mx, self.__name__, event)
                            self.notifyListeners(evt)

                hosts_enrichment = domain_item.get("hosts_enrichment")
                if hosts_enrichment:
                    for host_enrichment in hosts_enrichment:
                        if host_enrichment.get("country"):
                            evt = SpiderFootEvent('COUNTRY_NAME', host_enrichment["country"], self.__name__, event)
                            self.notifyListeners(evt)

                domain_technologies = domain_item.get("technologies")
                if domain_technologies:
                    for tech in domain_technologies:
                        if tech.get("version"):
                            evt = SpiderFootEvent('WEBSERVER_TECHNOLOGY', f"{tech['name']} {tech['version']}",
                                                  self.__name__, event)
                        else:
                            evt = SpiderFootEvent('WEBSERVER_TECHNOLOGY', tech['name'], self.__name__, event)

                        self.notifyListeners(evt)

                domain_cves = domain_item.get("cve_list")
                if domain_cves:
                    for cve in domain_cves:
                        evt = SpiderFootEvent('VULNERABILITY', cve["id"], self.__name__, event)
                        self.notifyListeners(evt)

                domain_whois = domain_item.get("whois_parsed")
                if domain_whois:
                    domain_whois_registrar = domain_whois.get("registrar")
                    if domain_whois_registrar:
                        if domain_whois_registrar.get("registrar_name"):
                            evt = SpiderFootEvent('DOMAIN_REGISTRAR',
                                                  domain_whois_registrar["registrar_name"], self.__name__,
                                                  event)
                            self.notifyListeners(evt)

                domain_http_extract = domain_item.get("http_extract")
                if domain_http_extract:

                    if domain_http_extract.get("http_status_code"):
                        evt = SpiderFootEvent('HTTP_CODE', str(domain_http_extract["http_status_code"]),
                                              self.__name__, event)
                        self.notifyListeners(evt)

                    domain_emails = domain_http_extract.get("emails")
                    if domain_emails:
                        for email in domain_emails:
                            evt = SpiderFootEvent('EMAILADDR', email, self.__name__, event)
                            self.notifyListeners(evt)

                domain_cert_summary = domain_item.get("cert_summary")
                if domain_cert_summary:
                    domain_cert_summary_subject = domain_cert_summary.get("subject")
                    if domain_cert_summary_subject:
                        if domain_cert_summary_subject.get("organization"):
                            evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUED',
                                                  domain_cert_summary_subject["organization"], self.__name__,
                                                  event)
                            self.notifyListeners(evt)

                    domain_cert_summary_issuer = domain_cert_summary.get("issuer")
                    if domain_cert_summary_issuer:
                        if domain_cert_summary_issuer.get("organization"):
                            evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUER',
                                                  domain_cert_summary_issuer["organization"], self.__name__,
                                                  event)
                            self.notifyListeners(evt)

                domain_trackers = domain_item.get("trackers")
                if domain_trackers:
                    if domain_trackers.get("google_analytics_key"):
                        evt = SpiderFootEvent("WEB_ANALYTICS_ID",
                                              f"Google Analytics: {domain_trackers.get('google_analytics_key')}",
                                              self.__name__, event)
                        self.notifyListeners(evt)

        while nextPageHasData:
            if self.checkForStop():
                return

            data = self.querySubdomains(eventData, currentOffset)
            if not data:
                nextPageHasData = False
                break

            data = data.get("data")
            if data is None:
                self.sf.debug("No subdomains found for domain " + eventData)
                nextPageHasData = False
                break
            else:
                records = data.get('items')
                if records:
                    for record in records:
                        domain = record.get('name')
                        if domain:
                            evt = SpiderFootEvent('RAW_RIR_DATA', str(record), self.__name__, event)
                            self.notifyListeners(evt)

                            domains.append(domain)
                            self.reportExtraData(record, event)

            # Calculate if there are any records in the next offset (page)
            if len(records) < self.limit:
                nextPageHasData = False
            currentOffset += self.limit

        for domain in set(domains):

            if domain in self.results:
                continue

            if not self.getTarget().matches(domain, includeChildren=True, includeParents=True):
                continue

            if self.opts['verify'] and not self.sf.resolveHost(domain):
                self.sf.debug(f"Host {domain} could not be resolved")
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", domain, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("INTERNET_NAME", domain, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_spyse class
