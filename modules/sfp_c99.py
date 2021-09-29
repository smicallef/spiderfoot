# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_c99
# Purpose:      SpiderFoot plug-in that queries c99 API
#
# Author:      Filip Aleksić <faleksicdev@gmail.com>
#
# Created:     2020-08-27
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_c99(SpiderFootPlugin):
    meta = {
        "name": "C99",
        "summary": "Queries the C99 API which offers various data (geo location, proxy detection, phone lookup, etc).",
        'flags': ["apikey"],
        "useCases": ["Footprint", "Passive", "Investigate"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://api.c99.nl/",
            "model": "COMMERCIAL_ONLY",
            "references": ["https://api.c99.nl/api_overview", "https://api.c99.nl/faq"],
            "apiKeyInstructions": [
                "Visit https://api.c99.nl",
                "Click shop in the top navigation or go to https://api.c99.nl/dashboard/shop",
                "Click purchase key on option 'C99.NL API KEY' (you can also purchase a 1 year key)",
                "You will receive your API key by email.",
            ],
            "favIcon": "https://api.c99.nl/favicon.ico",
            "logo": "https://api.c99.nl/assets/images/logo.png",
            "description": "C99 API service is versatile source of information. "
            "They offer over 57 different APIs of which 10 are integrated in this module. "
            "APIs that are integrated are subdomain finder, phone lookup, Skype resolver, "
            "IP to Skype, firewall technology WAF detector, domain history, "
            "IP to domains, IP geo location, proxy detector.",
        },
    }

    opts = {
        "api_key": "",
        "verify": True,
        "cohostsamedomain": False,
        "maxcohost": 100,
    }

    optdescs = {
        "api_key": "C99 API Key.",
        "verify": "Verify identified domains still resolve to the associated specified IP address.",
        "maxcohost": "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        "cohostsamedomain": "Treat co-hosted sites on the same target domain as co-hosting?",
    }

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "DOMAIN_NAME",
            "PHONE_NUMBER",
            "IP_ADDRESS",
            "USERNAME",
            "EMAILADDR",
        ]

    def producedEvents(self):
        return [
            "RAW_RIR_DATA",
            "GEOINFO",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "PROVIDER_TELCO",
            "PHYSICAL_ADDRESS",
            "PHYSICAL_COORDINATES",
            "PROVIDER_DNS",
            "IP_ADDRESS",
            "USERNAME",
            "ACCOUNT_EXTERNAL_OWNED",
            "WEBSERVER_TECHNOLOGY",
            "PROVIDER_HOSTING",
            "CO_HOSTED_SITE"
        ]

    def query(self, path, queryParam, queryData):
        res = self.sf.fetchUrl(
            f"https://api.c99.nl/{path}?key={self.opts['api_key']}&{queryParam}={queryData}&json",
            timeout=self.opts["_fetchtimeout"],
            useragent="SpiderFoot",
        )

        if res["code"] == "429":
            self.error("Reaching rate limit on C99 API")
            self.errorState = True
            return None

        if res["code"] == 400:
            self.error("Invalid request or API key on C99 API")
            self.errorState = True
            return None

        if res["content"] is None:
            self.info(f"No C99 info found for {queryData}")
            return None

        try:
            info = json.loads(res["content"])
        except Exception as e:
            self.errorState = True
            self.error(f"Error processing response from C99: {e}")
            return None

        if not info.get('success', False):
            return None

        return info

    def emitRawRirData(self, data, event):
        evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

    def emitPhoneData(self, phoneData, event):
        provider = phoneData.get("provider")
        carrier = phoneData.get("carrier")
        city = phoneData.get("city")
        countryName = phoneData.get("country_name")
        region = phoneData.get("region")
        found = False

        if provider or carrier:
            evt = SpiderFootEvent(
                "PROVIDER_TELCO",
                f"Provider: {provider}, Carrier: {carrier}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)
            found = True

        if city or countryName or region:
            evt = SpiderFootEvent(
                "PHYSICAL_ADDRESS",
                f"Country: {countryName}, Region: {region}, City: {city}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)
            found = True

        if found:
            self.emitRawRirData(phoneData, event)

    def emitSubDomainData(self, subDomainData, event):
        found = False

        for subDomainElem in subDomainData:
            if self.checkForStop():
                return

            subDomain = subDomainElem.get("subdomain", "").strip()

            if subDomain:
                self.emitHostname(subDomain, event)
                found = True

        if found:
            self.emitRawRirData(subDomainData, event)

    def emitDomainHistoryData(self, domainHistoryData, event):
        found = False

        for domainHistoryElem in domainHistoryData:
            if self.checkForStop():
                return

            ip = domainHistoryElem.get("ip_address")

            if self.sf.validIP(ip):
                evt = SpiderFootEvent(
                    "IP_ADDRESS",
                    ip,
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)
                found = True

        if found:
            self.emitRawRirData(domainHistoryData, event)

    def emitIpToSkypeData(self, data, event):
        skype = data.get("skype")

        if skype:
            evt = SpiderFootEvent(
                "ACCOUNT_EXTERNAL_OWNED",
                f"Skype [{skype}]",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)

            evt = SpiderFootEvent(
                "USERNAME",
                skype,
                self.__name__,
                event,
            )
            self.notifyListeners(evt)

            self.emitRawRirData(data, event)

    def emitIpToDomainsData(self, data, event):
        domains = data.get("domains")
        found = False

        if isinstance(domains, list):
            for domain in domains:
                if self.checkForStop():
                    return

                domain = domain.strip()
                if domain:
                    self.emitHostname(domain, event)
                    found = True

        if found:
            self.emitRawRirData(data, event)

    def emitProxyDetectionData(self, data, event):
        isProxy = data.get("proxy")

        if isProxy:
            evt = SpiderFootEvent(
                "WEBSERVER_TECHNOLOGY",
                f"Server is proxy: {isProxy}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)
            self.emitRawRirData(data, event)

    def emitGeoIPData(self, data, event):
        found = False

        hostName = data.get("hostname", "").strip()
        if hostName:
            self.emitHostname(hostName, event)
            found = True

        record = data.get("records")

        if record:
            country = record.get("country_name")
            region = record["region"].get("name") if record.get("region") else None
            city = record.get("city")
            postalCode = record.get("postal_code")
            latitude = record.get("latitude")
            longitude = record.get("longitude")
            provider = record.get("isp")

            if provider:
                evt = SpiderFootEvent(
                    "PROVIDER_HOSTING",
                    provider,
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)
                found = True

            if latitude and longitude:
                evt = SpiderFootEvent(
                    "PHYSICAL_COORDINATES",
                    f"{latitude}, {longitude}",
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)
                found = True

            if region or country or city or postalCode:
                evt = SpiderFootEvent(
                    "GEOINFO",
                    f"Country: {country}, Region: {region}, City: {city}, Postal code: {postalCode}",
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)
                found = True

        if found:
            self.emitRawRirData(data, event)

    def emitSkypeResolverData(self, data, event):
        ip = data.get("ip")
        ips = data.get("ips")
        found = False

        if ip and ip not in ips:
            evt = SpiderFootEvent(
                "IP_ADDRESS",
                ip,
                self.__name__,
                event,
            )
            self.notifyListeners(evt)
            found = True

        if isinstance(ips, list):
            found = True
            for ipElem in ips:
                if self.checkForStop():
                    return

                evt = SpiderFootEvent(
                    "IP_ADDRESS",
                    ipElem.strip(),
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)

        if found:
            self.emitRawRirData(data, event)

    def emitWafDetectorData(self, data, event):
        firewall = data.get("result")

        if firewall:
            evt = SpiderFootEvent(
                "WEBSERVER_TECHNOLOGY",
                f"Firewall detected: {firewall}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)
            self.emitRawRirData(data, event)

    def emitHostname(self, data, event):
        if not self.sf.validHost(data, self.opts['_internettlds']):
            return

        if self.opts["verify"] and not self.sf.resolveHost(data) and not self.sf.resolveHost6(data):
            self.debug(f"Host {data} could not be resolved.")
            if self.getTarget().matches(data):
                evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", data, self.__name__, event)
                self.notifyListeners(evt)
            return

        if self.getTarget().matches(data):
            evt = SpiderFootEvent('INTERNET_NAME', data, self.__name__, event)
            self.notifyListeners(evt)
            if self.sf.isDomain(data, self.opts['_internettlds']):
                evt = SpiderFootEvent('DOMAIN_NAME', data, self.__name__, event)
                self.notifyListeners(evt)
            return

        if self.cohostcount < self.opts['maxcohost']:
            if self.opts["verify"] and not self.sf.validateIP(data, event.data):
                self.debug("Host no longer resolves to our IP.")
                return

            if not self.opts["cohostsamedomain"]:
                if self.getTarget().matches(data, includeParents=True):
                    self.debug(
                        f"Skipping {data} because it is on the same domain."
                    )
                    return

            if self.cohostcount < self.opts["maxcohost"]:
                evt = SpiderFootEvent("CO_HOSTED_SITE", data, self.__name__, event)
                self.notifyListeners(evt)
                self.cohostcount += 1

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # Once we are in this state, return immediately.
        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error("You enabled sfp_c99, but did not set an API key!")
            self.errorState = True
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "PHONE_NUMBER":
            phoneData = self.query("phonelookup", "number", eventData)
            phoneData = phoneData.get("details") if phoneData else None

            if phoneData:
                self.emitPhoneData(phoneData, event)

        if eventName == "DOMAIN_NAME":
            subDomainData = self.query("subdomainfinder", "domain", eventData)
            subDomainData = (
                subDomainData.get("subdomains") if subDomainData is not None else None
            )

            if isinstance(subDomainData, list):
                self.emitSubDomainData(subDomainData, event)

            domainHistoryData = self.query("domainhistory", "domain", eventData)
            domainHistoryData = (
                domainHistoryData.get("result") if domainHistoryData else None
            )

            if isinstance(domainHistoryData, list):
                self.emitDomainHistoryData(domainHistoryData, event)

            wafDetectorData = self.query("firewalldetector", "url", eventData)

            if wafDetectorData:
                self.emitWafDetectorData(wafDetectorData, event)

        if eventName == "IP_ADDRESS":
            ipToSkypeData = self.query("ip2skype", "ip", eventData)

            if ipToSkypeData:
                self.emitIpToSkypeData(ipToSkypeData, event)

            ipToDomainsData = self.query("ip2domains", "ip", eventData)

            if ipToDomainsData:
                self.emitIpToDomainsData(ipToDomainsData, event)

            proxyDetectionData = self.query("proxydetector", "ip", eventData)

            if proxyDetectionData:
                self.emitProxyDetectionData(proxyDetectionData, event)

            geoIPData = self.query("geoip", "host", eventData)

            if geoIPData:
                self.emitGeoIPData(geoIPData, event)

        if eventName == "USERNAME":
            skypeResolverData = self.query("skyperesolver", "username", eventData)

            if skypeResolverData:
                self.emitSkypeResolverData(skypeResolverData, event)


# End of sfp_c99 class
