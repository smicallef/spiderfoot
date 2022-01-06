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
        'summary': "Search Spyse.com Internet assets registry for information about domains, IP addresses, host info, potential vulnerabilities, passive DNS, etc.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://spyse.com",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://spyse.com/api",
                "https://spyse-dev.readme.io/reference/quick-start",
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
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "DOMAIN_NAME",
            "INTERNET_NAME",
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "DOMAIN_NAME",
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "CO_HOSTED_SITE",
            "RAW_RIR_DATA",
            "TCP_PORT_OPEN",
            "TCP_PORT_OPEN_BANNER",
            "OPERATING_SYSTEM",
            "WEBSERVER_HTTPHEADERS",
            "SOFTWARE_USED",
            "COMPANY_NAME",
            "WEBSERVER_TECHNOLOGY",
            "PROVIDER_MAIL",
            "PROVIDER_DNS",
            "DNS_TEXT",
            "DNS_SPF",
            "GEOINFO",
            "WEB_ANALYTICS_ID",
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "VULNERABILITY_GENERAL",
            "SSL_CERTIFICATE_ISSUED",
            "SSL_CERTIFICATE_ISSUER",
            "EMAILADDR",
            "DOMAIN_REGISTRAR",
            "HTTP_CODE",
        ]

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
        """Query IPv4 port lookup

        https://spyse-dev.readme.io/reference/ips#ip_details

        Args:
            qry (str): IP address

        Returns:
            dict: JSON formatted results
        """
        if not self.sf.validIP(qry):
            self.info(f"Invalid IPv4 address: {qry}")
            return None

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
            qry (str): IPv4/IPv6 address
            currentOffset (int): start from this search result offset

        Returns:
            dict: JSON formatted results
        """
        headers = {
            'Accept': "application/json",
            'Content-Type': "application/json",
            'Authorization': "Bearer " + self.opts['api_key']
        }

        if self.sf.validIP(qry):
            search_key = 'dns_a'
        elif self.sf.validIP6(qry):
            search_key = 'dns_aaaa'
        else:
            self.info(f"Invalid IP address: {qry}")
            return None

        body = {
            "search_params": [
                {
                    search_key: {
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
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent'],
            postData=json.dumps(body)
        )

        time.sleep(self.opts['delay'])

        return self.parseAPIResponse(res)

    def parseAPIResponse(self, res):
        """Parse API response

        https://spyse-dev.readme.io/reference/quick-start

        Args:
            res: Spyse API HTTP response

        Returns:
            dict: JSON formatted results
        """
        if res['code'] == '400':
            self.error("Malformed request")
            return None

        if res['code'] == '401':
            self.error("Unauthorized")
            self.errorState = True
            return None

        if res['code'] == '402':
            self.error("Request limit exceeded")
            self.errorState = True
            return None

        if res['code'] == '403':
            if res['content'] and "the applied search parameter isn't allowed for your subscription plan" in res['content']:
                self.error("The applied search parameter isn't allowed for your subscription plan")
            else:
                self.error("Authentication failed")
                self.errorState = True
            return None

        # Future proofing - Spyse does not implement rate limiting
        if res['code'] == '429':
            self.error("You are being rate-limited by Spyse")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error("Failed to retrieve content from Spyse")
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.debug(f"Error processing JSON response: {e}")
            return None

        if data.get('error'):
            self.info(f"Received error from Spyse: {data.get('error')}")

        return data

    def handleEvent(self, event):
        if self.errorState:
            return

        if self.opts['api_key'] == '':
            self.error(f"You enabled {self.__class__.__name__} but did not set an API key!")
            self.errorState = True
            return

        if event.data in self.results:
            return

        self.results[event.data] = True

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        if event.eventType == 'IP_ADDRESS':
            self.retrieve_cohosts(event)
            self.retrieve_ports(event)
        elif event.eventType == "IPV6_ADDRESS":
            self.retrieve_cohosts(event)
        elif event.eventType in ["DOMAIN_NAME", "INTERNET_NAME"]:
            self.retrieve_domain_info(event)
            self.retrieve_subdomains(event)
        else:
            self.debug(f"Unexpected event type {event.eventType}, skipping")

    def retrieve_cohosts(self, event):
        cohosts = list()
        currentOffset = 0
        eventData = event.data

        while True:
            if self.checkForStop():
                break

            if self.errorState:
                break

            data = self.queryDomainsOnIP(eventData, currentOffset)
            if not data:
                break

            data = data.get("data")
            if data is None:
                self.debug(f"No co-hosts found on IP address {eventData}")
                break

            records = data.get('items')
            if records:
                for record in records:
                    domain = record.get('name')
                    if domain:
                        evt = SpiderFootEvent('RAW_RIR_DATA', str(record), self.__name__, event)
                        self.notifyListeners(evt)
                        cohosts.append(domain)

            # Calculate if there are any records in the next offset (page)
            if len(records) < self.limit:
                break
            currentOffset += self.limit

        for co in set(cohosts):
            if co in self.results:
                continue

            if self.opts['verify'] and not self.sf.validateIP(co, eventData):
                self.debug(f"Host {co} no longer resolves to {eventData}")
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

    def retrieve_ports(self, event):
        eventData = event.data

        data = self.queryIPPort(eventData)
        if not data:
            return

        data = data.get("data")

        if data is None:
            self.debug(f"No open ports found for IP {eventData}")
            return

        records = data.get('items')
        if not records:
            return

        for record in records:
            geoinfo = record.get("geo_info")
            if geoinfo:
                city = geoinfo.get("city")
                country = geoinfo.get("country")
                location = ', '.join([_f for _f in [city, country] if _f])
                if location:
                    evt = SpiderFootEvent('GEOINFO', location, self.__name__, event)
                    self.notifyListeners(evt)

            cve_list = record.get("cve_list")
            if cve_list:
                for cve in cve_list:
                    cve_id = cve.get('id')
                    if cve_id:
                        etype, cvetext = self.sf.cveInfo(cve_id)
                        evt = SpiderFootEvent(etype, cvetext, self.__name__, event)
                        self.notifyListeners(evt)

            technologies = record.get("technologies")
            if technologies:
                for tech in technologies:
                    name = tech.get("name")

                    if not name:
                        continue

                    version = tech.get("version")
                    software = ' '.join(filter(None, [name, version]))
                    if software:
                        evt = SpiderFootEvent('SOFTWARE_USED', f"{software}", self.__name__, event)
                        self.notifyListeners(evt)

            ports = record.get('ports')
            if not ports:
                continue

            for port_data in ports:
                if not port_data:
                    continue

                evt = SpiderFootEvent('RAW_RIR_DATA', json.dumps(port_data), self.__name__, event)
                self.notifyListeners(evt)

                port = port_data.get('port')

                if not port:
                    continue

                ip_port = f"{eventData}:{port}"

                if ip_port in self.results:
                    continue

                self.results[ip_port] = True

                port_event = SpiderFootEvent('TCP_PORT_OPEN', ip_port, self.__name__, event)
                self.notifyListeners(port_event)

                banner = port_data.get('banner')
                if banner:
                    evt = SpiderFootEvent('TCP_PORT_OPEN_BANNER', json.dumps(banner), self.__name__, port_event)
                    self.notifyListeners(evt)

    def retrieve_domain_info(self, event):
        eventData = event.data
        if event.module == "sfp_spyse" and (self.getTarget().targetValue in event.data):
            return

        domain_details = self.queryDomainDetails(eventData)
        if not domain_details:
            return

        domain_details_data = domain_details.get("data", {}).get("items", [])
        if len(domain_details_data) == 0:
            return

        domain_item = domain_details_data[0]
        if domain_item.get("organizations"):
            for org in domain_item.get("organizations", []):
                crunchbase = org.get('crunchbase')
                if crunchbase:
                    if crunchbase.get("is_primary", False):
                        org_name = crunchbase.get("legal_name")
                        if not org_name:
                            org_name = crunchbase.get("name")
                        if org_name:
                            evt = SpiderFootEvent('COMPANY_NAME', org_name, self.__name__, event)
                            self.notifyListeners(evt)

        domain_dns = domain_item.get("dns_records")
        if domain_dns:
            domain_dns_a_records = domain_dns.get("A")
            if domain_dns_a_records:
                for dns_A in domain_dns_a_records:
                    if dns_A:
                        evt = SpiderFootEvent('IP_ADDRESS', dns_A, self.__name__, event)
                        self.notifyListeners(evt)

            domain_dns_aaaa_records = domain_dns.get("AAAA")
            if domain_dns_aaaa_records:
                for dns_AAAA in domain_dns_aaaa_records:
                    if dns_AAAA:
                        evt = SpiderFootEvent('IPV6_ADDRESS', dns_AAAA, self.__name__, event)
                        self.notifyListeners(evt)

            domain_dns_spf_records = domain_dns.get("SPF")
            if domain_dns_spf_records:
                for dns_spf in domain_dns_spf_records:
                    if dns_spf:
                        dns_spf_raw = dns_spf.get("raw")
                        if dns_spf_raw:
                            evt = SpiderFootEvent('DNS_SPF', dns_spf_raw, self.__name__, event)
                            self.notifyListeners(evt)

            domain_dns_txt_records = domain_dns.get("TXT")
            if domain_dns_txt_records:
                for dns_txt in domain_dns_txt_records:
                    if dns_txt:
                        evt = SpiderFootEvent('DNS_TEXT', dns_txt, self.__name__, event)
                        self.notifyListeners(evt)

            domain_dns_ns_records = domain_dns.get("NS")
            if domain_dns_ns_records:
                for dns_ns in domain_dns_ns_records:
                    if dns_ns:
                        evt = SpiderFootEvent('PROVIDER_DNS', dns_ns, self.__name__, event)
                        self.notifyListeners(evt)

            domain_dns_mx_records = domain_dns.get("MX")
            if domain_dns_mx_records:
                for dns_mx in domain_dns_mx_records:
                    if dns_mx:
                        evt = SpiderFootEvent('PROVIDER_MAIL', dns_mx, self.__name__, event)
                        self.notifyListeners(evt)

        hosts_enrichment = domain_item.get("hosts_enrichment")
        if hosts_enrichment:
            for host_enrichment in hosts_enrichment:
                city = host_enrichment.get("city")
                country = host_enrichment.get("country")
                location = ', '.join([_f for _f in [city, country] if _f])
                if location:
                    evt = SpiderFootEvent('GEOINFO', location, self.__name__, event)
                    self.notifyListeners(evt)

        domain_technologies = domain_item.get("technologies")
        if domain_technologies:
            for tech in domain_technologies:
                name = tech.get("name")

                if not name:
                    continue

                version = tech.get("version")
                software = ' '.join(filter(None, [name, version]))
                if software:
                    evt = SpiderFootEvent('WEBSERVER_TECHNOLOGY', f"{software}", self.__name__, event)
                    self.notifyListeners(evt)

        domain_cves = domain_item.get("cve_list")
        if domain_cves:
            for cve in domain_cves:
                cve_id = cve.get('id')
                if cve_id:
                    etype, cvetext = self.sf.cveInfo(cve_id)
                    evt = SpiderFootEvent(etype, cvetext, self.__name__, event)
                    self.notifyListeners(evt)

        domain_whois = domain_item.get("whois_parsed")
        if domain_whois:
            domain_whois_registrar = domain_whois.get("registrar")
            if domain_whois_registrar:
                registrar_name = domain_whois_registrar.get("registrar_name")
                if registrar_name:
                    evt = SpiderFootEvent('DOMAIN_REGISTRAR', registrar_name, self.__name__, event)
                    self.notifyListeners(evt)

        domain_http_extract = domain_item.get("http_extract")
        if domain_http_extract:
            http_status_code = domain_http_extract.get("http_status_code")
            if http_status_code:
                evt = SpiderFootEvent('HTTP_CODE', str(http_status_code), self.__name__, event)
                self.notifyListeners(evt)

            http_headers = domain_http_extract.get("http_headers")
            if http_headers:
                evt = SpiderFootEvent('WEBSERVER_HTTPHEADERS', str(http_headers), self.__name__, event)
                self.notifyListeners(evt)

            domain_emails = domain_http_extract.get("emails")
            if domain_emails:
                for email in domain_emails:
                    if self.sf.validEmail(email):
                        evt = SpiderFootEvent('EMAILADDR', email, self.__name__, event)
                        self.notifyListeners(evt)

        domain_cert_summary = domain_item.get("cert_summary")
        if domain_cert_summary:
            domain_cert_summary_subject = domain_cert_summary.get("subject")
            if domain_cert_summary_subject:
                cert_issued = domain_cert_summary_subject.get("organization")
                if cert_issued:
                    evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUED', cert_issued, self.__name__, event)
                    self.notifyListeners(evt)

            domain_cert_summary_issuer = domain_cert_summary.get("issuer")
            if domain_cert_summary_issuer:
                cert_issuer = domain_cert_summary_issuer.get("organization")
                if cert_issuer:
                    evt = SpiderFootEvent('SSL_CERTIFICATE_ISSUER', cert_issuer, self.__name__, event)
                    self.notifyListeners(evt)

        domain_trackers = domain_item.get("trackers")
        if domain_trackers:
            google_analytics_key = domain_trackers.get("google_analytics_key")
            if google_analytics_key:
                evt = SpiderFootEvent("WEB_ANALYTICS_ID", f"Google Analytics: {google_analytics_key}", self.__name__, event)
                self.notifyListeners(evt)

    def retrieve_subdomains(self, event):
        if event.module == "sfp_spyse" and (self.getTarget().targetValue in event.data):
            return

        eventData = event.data
        domains = list()
        currentOffset = 0
        while True:
            if self.checkForStop():
                break

            if self.errorState:
                break

            data = self.querySubdomains(eventData, currentOffset)
            if not data:
                break

            data = data.get("data")
            if data is None:
                self.debug(f"No subdomains found for domain {eventData}")
                break

            records = data.get('items')
            if records:
                for record in records:
                    print(record)
                    domain = record.get('name')
                    if domain:
                        evt = SpiderFootEvent('RAW_RIR_DATA', str(record), self.__name__, event)
                        self.notifyListeners(evt)
                        domains.append(domain)

            # Calculate if there are any records in the next offset (page)
            if len(records) < self.limit:
                break

            currentOffset += self.limit

        for domain in set(domains):
            if domain in self.results:
                continue

            if not self.getTarget().matches(domain, includeChildren=True, includeParents=True):
                continue

            if self.opts['verify'] and not self.sf.resolveHost(domain) and not self.sf.resolveHost6(domain):
                self.debug(f"Host {domain} could not be resolved")
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", domain, self.__name__, event)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("INTERNET_NAME", domain, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_spyse class
