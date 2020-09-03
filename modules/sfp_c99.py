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
from spiderfoot import SpiderFootPlugin, SpiderFootEvent


class sfp_c99(SpiderFootPlugin):
    meta = {
        "name": "C99",
        "summary": "This module queries c99 API that offers various data (geo location, proxy detection, phone lookup, etc).",
        "flags": ["apikey"],
        "useCases": ["Footprint", "Passive", "Investigate"],
        "categories": ["Content Analysis"],
        "dataSource": {
            "website": "https://api.c99.nl/",
            "model": "COMMERCIAL_ONLY",
            "references": ["https://api.c99.nl/api_overview", "https://api.c99.nl/faq"],
            "apiKeyInstructions": [
                "Visit api.c99.nl",
                "Press shop in navigation or go to https://api.c99.nl/dashboard/shop",
                "Press purchase key on option 'C99.NL API KEY' (you can also buy 1 year key if you want)",
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

    opts = {"api_key": "", "verify": True}

    optdescs = {
        "api_key": "C99 API Key.",
        "verify": "Verify identified domains still resolve to the associated specified IP address.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

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
        ]

    def query(self, path, queryParam, queryData):
        res = self.sf.fetchUrl(
            f"https://api.c99.nl/{path}?key={self.opts['api_key']}&{queryParam}={queryData}&json",
            timeout=self.opts["_fetchtimeout"],
            useragent="SpiderFoot",
        )

        if res["code"] == "429":
            self.sf.error("Reaching rate limit on C99 API", False)
            self.errorState = True
            return None

        if res["code"] == 400:
            self.sf.error("Invalid request or API key on C99 API", False)
            self.errorState = True
            return None

        if res["content"] is None:
            self.sf.info(f"No C99 info found for {queryData}")
            return None

        try:
            info = json.loads(res["content"])
        except Exception as e:
            self.errorState = True
            self.sf.error(f"Error processing response from C99: {e}", False)
            return None

        return info

    def emitRawRirData(self, data, event):
        evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
        self.notifyListeners(evt)

    def emitPhoneData(self, phoneData, event):
        self.emitRawRirData(phoneData, event)

        provider = phoneData.get("provider")
        carrier = phoneData.get("carrier")
        city = phoneData.get("city")
        countryName = phoneData.get("country_name")
        region = phoneData.get("region")

        if provider or carrier:
            evt = SpiderFootEvent(
                "PROVIDER_TELCO",
                f"Provider: {provider}, Carrier: {carrier}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)

        if city or countryName or region:
            evt = SpiderFootEvent(
                "PHYSICAL_ADDRESS",
                f"Country: {countryName}, Region: {region}, City: {city}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)

    def emitSubDomainData(self, subDomainData, event):
        self.emitRawRirData(subDomainData, event)

        for subDomainElem in subDomainData:
            if self.checkForStop():
                return None

            subDomain = subDomainElem.get("subdomain")
            ip = subDomainElem.get("ip")
            cloudFlare = subDomainElem.get("cloudflare")

            if subDomain:
                if self.opts["verify"] and not self.sf.resolveHost(subDomain):
                    self.sf.debug(
                        f"Host {subDomain} could not be resolved for {event.data}"
                    )
                    evt = SpiderFootEvent(
                        "INTERNET_NAME_UNRESOLVED",
                        f"Sub domain: {subDomain}, IP: {ip}, CloudFlare: {cloudFlare}",
                        self.__name__,
                        event,
                    )
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent(
                        "INTERNET_NAME",
                        f"Sub domain: {subDomain}, IP: {ip}, CloudFlare: {cloudFlare}",
                        self.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

    def emitDomainHistoryData(self, domainHistoryData, event):
        self.emitRawRirData(domainHistoryData, event)

        for domainHistoryElem in domainHistoryData:
            if self.checkForStop():
                return None

            date = domainHistoryElem.get("date")
            ip = domainHistoryElem.get("ip_address")

            if ip:
                evt = SpiderFootEvent(
                    "IP_ADDRESS",
                    f"IP: {ip}, Date: {date}",
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)

    def emitIpToSkypeData(self, data, event):
        self.emitRawRirData(data, event)

        skype = data.get("skype")

        if skype:
            evt = SpiderFootEvent(
                "ACCOUNT_EXTERNAL_OWNED",
                skype,
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

    def emitIpToDomainsData(self, data, event):
        self.emitRawRirData(data, event)

        domains = data.get("domains")

        if isinstance(domains, list):
            for domain in domains:
                if self.checkForStop():
                    return None

                if self.opts["verify"] and not self.sf.resolveHost(domain):
                    self.sf.debug(
                        f"Host {domain} could not be resolved for {event.data}"
                    )
                    evt = SpiderFootEvent(
                        "INTERNET_NAME_UNRESOLVED",
                        domain,
                        self.__name__,
                        event,
                    )
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent(
                        "INTERNET_NAME",
                        domain,
                        self.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

    def emitProxyDetectionData(self, data, event):
        self.emitRawRirData(data, event)
        isProxy = data.get("proxy")

        if isProxy:
            evt = SpiderFootEvent(
                "WEBSERVER_TECHNOLOGY",
                f"Server is proxy: {isProxy}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)

    def emitGeoIPData(self, data, event):
        self.emitRawRirData(data, event)

        hostName = data.get("hostname")
        if hostName:
            if self.opts["verify"] and not self.sf.resolveHost(hostName):
                self.sf.debug(f"Host {hostName} could not be resolved for {event.data}")
                evt = SpiderFootEvent(
                    "INTERNET_NAME_UNRESOLVED",
                    hostName,
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent(
                    "INTERNET_NAME",
                    hostName,
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)

        record = data.get("records")

        if record:
            continent = (
                record["continent"].get("name") if record.get("continent") else None
            )
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

            if latitude and longitude:
                evt = SpiderFootEvent(
                    "PHYSICAL_COORDINATES",
                    f"{latitude}, {longitude}",
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)

            if continent or country or region or city or postalCode:
                evt = SpiderFootEvent(
                    "GEOINFO",
                    f"Continent: {continent}, Country: {country}, Region: {region}, City: {city}, Postal code: {postalCode}",
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)

    def emitSkypeResolverData(self, data, event):
        self.emitRawRirData(data, event)

        ip = data.get("ip")
        ips = data.get("ips")

        if ip and ip not in ips:
            evt = SpiderFootEvent(
                "IP_ADDRESS",
                ip,
                self.__name__,
                event,
            )
            self.notifyListeners(evt)

        if isinstance(ips, list):
            for ipElem in ips:
                if self.checkForStop():
                    return None

                evt = SpiderFootEvent(
                    "IP_ADDRESS",
                    ipElem.strip(),
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)

    def emitWafDetectorData(self, data, event):
        self.emitRawRirData(data, event)
        firewall = data.get("result")

        if firewall:
            evt = SpiderFootEvent(
                "WEBSERVER_TECHNOLOGY",
                f"Firewall detected: {firewall}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # Once we are in this state, return immediately.
        if self.errorState:
            return None

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.sf.error("You enabled sfp_c99, but did not set an API key!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return None

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
