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
from sflib import SpiderFootPlugin, SpiderFootEvent


class sfp_c99(SpiderFootPlugin):
    """C99:Footprint,Passive,Investigate:Content Analysis:apikey:Obtain data from c99 API which offers various data (geo location, proxy detection, phone lookup, etc)."""

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
                "You should get your key on your email'",
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

    opts = {"api_key": "", "response_type": "JSON", "verify": True}

    optdescs = {
        "api_key": "C99 API Key.",
        "response_type": "Do you want to query the API with response in Plain text or JSON (write 'Plain' or 'JSON')",
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
            "PHYSICAL_COORDINATES" "PROVIDER_DNS",
            "IP_ADDRESS",
            "USERNAME",
            "ACCOUNT_EXTERNAL_OWNED",
            "WEBSERVER_TECHNOLOGY",
            "PROVIDER_HOSTING",
        ]

    def plainPhoneLookupParser(self, data):
        if "invalid" in data.lower() or "unable" in data.lower():
            return None
        lines = data.split("<br>")
        responseDict = dict(
            line.strip().split(": ")
            for line in lines
            if ": " in line and len(line.strip().split(": ")) == 2
        )
        result = {
            "details": {
                "country_name": responseDict.get("Country"),
                "provider": responseDict.get("Provider"),
                "carrier": responseDict.get("Carrier"),
                "city": responseDict.get("City"),
                "region": responseDict.get("Region"),
            }
        }

        return result

    def plainSubdomainFinderParser(self, data):
        if "make sure" in data.lower():
            return None

        lines = data.split("<br>")
        result = {}
        result["subdomains"] = []
        for line in lines:
            line = line.strip()
            if len(line) > 0:
                result["subdomains"].append({"subdomain": line})

        return result

    def plainDomainHistoryParser(self, data):
        if "could not find" in data.lower():
            return None

        result = {}
        arr = []

        lines = data.split(",")
        for line in lines:
            if len(line) == 0:
                continue

            entry = line.split("] ")
            if len(entry) != 2:
                continue

            arr.append({"ip_address": entry[1], "date": entry[0].strip()[1:]})

        result["result"] = arr
        return result

    def plainIPToSkypeParser(self, data):
        if "error" in data.lower():
            return None

        return {"skype": data.strip()}

    def plainIPToDomainsParser(self, data):
        if "no domains" in data.lower():
            return None

        lines = data.split("<br>")
        return {"domains": [line.strip() for line in lines if len(line.strip()) > 0]}

    def plainProxyDetectorParser(self, data):
        if "invalid" in data.lower():
            return None

        return {"proxy": not ("no proxy detected" in data.lower())}

    def plainGeoIPParser(self, data):
        if "not a valid" in data.lower() or "not in the database" in data.lower():
            return None

        lines = data.split("<br>")
        responseDict = dict(
            line.strip().split(": ")
            for line in lines
            if ": " in line
            and len(line.strip().split(": ")) == 2
            and "unknown" not in line
        )
        result = {
            "hostname": responseDict.get("Hostname"),
            "records": {
                "country_name": responseDict.get("Country"),
                "region": {"name": responseDict.get("Region")},
                "city": responseDict.get("City"),
                "continent": {"name": responseDict.get("Continent")},
                "isp": responseDict.get("ISP"),
            },
        }

        return result

    def plainSkypeResolverParser(self, data):
        if "error" in data.lower():
            return None

        lines = data.split(",")
        arr = []
        for line in lines:
            line = line.strip()
            if len(line) == 0:
                continue

            arr.append(line)

        if len(arr) == 0:
            return None

        return {"ip": arr[0], "ips": arr}

    def plainFirewallDetectorParser(self, data):
        if "invalid url" in data.lower() or "no firewall" in data.lower():
            return None

        return {"result": data}

    def parseResponse(self, response, path):
        if self.opts["response_type"].lower() == "plain":
            endpointTypes = {
                "phonelookup": self.plainPhoneLookupParser,
                "subdomainfinder": self.plainSubdomainFinderParser,
                "firewalldetector": self.plainFirewallDetectorParser,
                "domainhistory": self.plainDomainHistoryParser,
                "ip2skype": self.plainIPToSkypeParser,
                "ip2domains": self.plainIPToDomainsParser,
                "proxydetector": self.plainProxyDetectorParser,
                "geoip": self.plainGeoIPParser,
                "skyperesolver": self.plainSkypeResolverParser,
            }
            try:
                return endpointTypes[path](response)
            except Exception as e:
                self.errorState = True
                self.sf.error(f"Error processing response from C99: {e}", False)
                return None

        return json.loads(response)

    def query(self, path, queryParam, queryData):
        responseType = "" if self.opts["response_type"].lower() == "plain" else "json"
        res = self.sf.fetchUrl(
            f"https://api.c99.nl/{path}?key={self.opts['api_key']}&{queryParam}={queryData}&{responseType}",
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
            info = self.parseResponse(res["content"], path)
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

        if provider is not None or carrier is not None:
            evt = SpiderFootEvent(
                "PROVIDER_TELCO",
                f"Provider: {provider}, Carrier: {carrier}",
                self.__name__,
                event,
            )
            self.notifyListeners(evt)

        if city is not None or countryName is not None or region is not None:
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

            if subDomain is not None:
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

            if ip is not None:
                evt = SpiderFootEvent(
                    "IP_ADDRESS",
                    f"IP: {ip}, Date: {date}",
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)

    def emitIPToSkypeData(self, data, event):
        self.emitRawRirData(data, event)

        skype = data.get("skype")

        if skype is not None:
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

    def emitIPToDomainsData(self, data, event):
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

        if isProxy is not None:
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
        if (
            hostName is not None
            and self.opts["verify"]
            and not self.sf.resolveHost(hostName)
        ):
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

        if record is not None:
            continent = (
                record["continent"].get("name")
                if record.get("continent") is not None
                else None
            )
            country = record.get("country_name")
            region = (
                record["region"].get("name")
                if record.get("region") is not None
                else None
            )
            city = record.get("city")
            postalCode = record.get("postal_code")
            latitude = record.get("latitude")
            longitude = record.get("longitude")
            provider = record.get("isp")

            if provider is not None:
                evt = SpiderFootEvent(
                    "PROVIDER_HOSTING",
                    provider,
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)

            if latitude is not None and longitude is not None:
                evt = SpiderFootEvent(
                    "PHYSICAL_COORDINATES",
                    f"{latitude}, {longitude}",
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)

            if (
                continent is not None
                or country is not None
                or region is not None
                or city is not None
                or postalCode is not None
            ):
                evt = SpiderFootEvent(
                    "GEOINFO",
                    f"Continent: {continent}, Country: {country}, Region: {region}, City: {city}, Postal code: {postalCode}",
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)

    def emitSkypeResolverData(self, data, event):
        self.emitRawRirData(data, event)

        IP = data.get("ip")
        IPs = data.get("ips")

        if IP is not None and IP not in IPs:
            evt = SpiderFootEvent(
                "IP_ADDRESS",
                IP,
                self.__name__,
                event,
            )
            self.notifyListeners(evt)

        if isinstance(IPs, list):
            for IPElem in IPs:
                if self.checkForStop():
                    return None

                evt = SpiderFootEvent(
                    "IP_ADDRESS",
                    IPElem.strip(),
                    self.__name__,
                    event,
                )
                self.notifyListeners(evt)

    def emitWafDetectorData(self, data, event):
        self.emitRawRirData(data, event)
        firewall = data.get("result")

        if firewall is not None:
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

        if (
            self.opts["response_type"].lower() != "plain"
            and self.opts["response_type"].lower() != "json"
        ):
            self.sf.info(
                "You enabled sfp_c99 ,but did not set response type to json or plain! JSON will be used by default"
            )
            self.opts["response_type"] = "json"

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return None

        self.results[eventData] = True

        if eventName == "PHONE_NUMBER":
            phoneData = self.query("phonelookup", "number", eventData)
            phoneData = phoneData.get("details") if phoneData is not None else None

            if phoneData is not None:
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
                domainHistoryData.get("result")
                if domainHistoryData is not None
                else None
            )

            if isinstance(domainHistoryData, list):
                self.emitDomainHistoryData(domainHistoryData, event)

            wafDetectorData = self.query("firewalldetector", "url", eventData)

            if wafDetectorData is not None:
                self.emitWafDetectorData(wafDetectorData, event)

        if eventName == "IP_ADDRESS":
            IPToSkypeData = self.query("ip2skype", "ip", eventData)

            if IPToSkypeData is not None:
                self.emitIPToSkypeData(IPToSkypeData, event)

            IPToDomainsData = self.query("ip2domains", "ip", eventData)

            if IPToDomainsData is not None:
                self.emitIPToDomainsData(IPToDomainsData, event)

            proxyDetectionData = self.query("proxydetector", "ip", eventData)

            if proxyDetectionData is not None:
                self.emitProxyDetectionData(proxyDetectionData, event)

            geoIPData = self.query("geoip", "host", eventData)

            if geoIPData is not None:
                self.emitGeoIPData(geoIPData, event)

        if eventName == "USERNAME":
            skypeResolverData = self.query("skyperesolver", "username", eventData)

            if skypeResolverData is not None:
                self.emitSkypeResolverData(skypeResolverData, event)


# End of sfp_c99 class
