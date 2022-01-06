# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_onyphe
# Purpose:      SpiderFoot plug-in to check if the IP is included on Onyphe
#               data (threat list, geo-location, pastries, vulnerabilities)
#
# Author:      Filip Aleksić <faleksicdev@gmail.com>
#
# Created:     2020-08-21
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
from datetime import datetime

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_onyphe(SpiderFootPlugin):

    meta = {
        "name": "Onyphe",
        "summary": "Check Onyphe data (threat list, geo-location, pastries, vulnerabilities)  about a given IP.",
        'flags': ["apikey"],
        "useCases": ["Footprint", "Passive", "Investigate"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://www.onyphe.io",
            "model": "FREE_AUTH_LIMITED",
            "references": ["https://www.onyphe.io/documentation/api"],
            "apiKeyInstructions": [
                "Visit https://www.onyphe.io/login/#register",
                "Register a free account",
                "You should receive your API key on your email, or you can get it by yourself following next steps",
                "Go to your account settings https://www.onyphe.io/auth/account",
                "The API key is listed under 'API Key'",
            ],
            "favIcon": "https://www.onyphe.io/favicon.ico",
            "logo": "https://www.onyphe.io/img/logo-solo.png",
            "description": "ONYPHE is a search engine for open-source "
            "and cyber threat intelligence data collected by crawling "
            "various sources available on the Internet or by listening "
            "to Internet background noise. They make this data available "
            "through API that we use. We check their data to see following "
            "information about the IP: geo-location, does it have some "
            "vulnerabilities, is it on some pastries (PasteBin) and "
            "is it on their threat list",
        },
    }

    opts = {
        "api_key": "",
        "paid_plan": False,
        "max_page": 10,
        "verify": True,
        "age_limit_days": 30,
        "cohostsamedomain": False,
        "maxcohost": 100,
    }
    optdescs = {
        "api_key": "Onyphe access token.",
        "paid_plan": "Are you using paid plan? Paid plan has pagination enabled",
        "max_page": "Maximum number of pages to iterate through. Onyphe has a maximum of 1000 pages (10,000 results). Only matters for paid plans",
        "verify": "Verify identified domains still resolve to the associated specified IP address.",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
        "maxcohost": "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        "cohostsamedomain": "Treat co-hosted sites on the same target domain as co-hosting?",
    }

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "IPV6_ADDRESS"]

    # What events this module produces
    def producedEvents(self):
        return [
            "GEOINFO",
            "MALICIOUS_IPADDR",
            "LEAKSITE_CONTENT",
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "VULNERABILITY_GENERAL",
            "RAW_RIR_DATA",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "PHYSICAL_COORDINATES",
        ]

    def query(self, endpoint, ip, page=1):
        retarr = list()

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"apikey {self.opts['api_key']}",
        }
        res = self.sf.fetchUrl(
            f"https://www.onyphe.io/api/v2/simple/{endpoint}/{ip}?page={page}",
            timeout=self.opts["_fetchtimeout"],
            useragent=self.opts["_useragent"],
            headers=headers,
        )

        if res["code"] == "429":
            self.error("Reaching rate limit on Onyphe API")
            self.errorState = True
            return None

        if res["code"] == 400:
            self.error("Invalid request or API key on Onyphe")
            self.errorState = True
            return None

        try:
            info = json.loads(res["content"])
            if "status" in info and info["status"] == "nok":
                self.error(
                    f"Unexpected error happened while requesting data from Onyphe. Error message: {info.get('text', '')}"
                )
                self.errorState = True
                return None
            elif "results" not in info or info["results"] == []:
                self.info(f"No Onyphe {endpoint} data found for {ip}")
                return None
        except Exception as e:
            self.debug(f"{e.__class__} {res['code']} {res['content']}")
            self.error("Error processing JSON response from Onyphe.")
            return None

        # Go through other pages if user has paid plan
        try:
            current_page = int(info["page"])
            if (
                self.opts["paid_plan"]
                and info.get("page")
                and int(info.get("max_page")) > current_page
            ):
                page = current_page + 1

                if page > self.opts["max_page"]:
                    self.error(
                        "Maximum number of pages from options for Onyphe reached."
                    )
                    return [info]
                retarr.append(info)
                response = self.query(endpoint, ip, page)
                if response:
                    retarr.extend(response)
            else:
                retarr.append(info)

        except ValueError:
            self.error(
                f"Unexpected value for page in response from Onyphe, url: https://www.onyphe.io/api/v2/simple/{endpoint}/{ip}?page={page}"
            )
            self.errorState = True
            return None

        return retarr

    def emitLocationEvent(self, location, eventData, event):
        if location is None:
            return
        self.info(f"Found location for {eventData}: {location}")

        evt = SpiderFootEvent("PHYSICAL_COORDINATES", location, self.__name__, event)
        self.notifyListeners(evt)

    def emitDomainData(self, response, eventData, event):
        domains = set()
        if response.get("domain") is not None and isinstance(
            response['domain'], list
        ):
            for dom in response['domain']:
                domains.add(dom)

        if response.get("subdomains") is not None and isinstance(
            response["subdomains"], list
        ):
            for subDomain in response["subdomains"]:
                domains.add(subDomain)

        for domain in domains:
            if self.getTarget().matches(domain):
                if self.opts['verify']:
                    if self.sf.resolveHost(domain) or self.sf.resolveHost6(domain):
                        evt = SpiderFootEvent('INTERNET_NAME', domain, self.__name__, event)
                    else:
                        evt = SpiderFootEvent('INTERNET_NAME_UNRESOLVED', domain, self.__name__, event)
                    self.notifyListeners(evt)

                if self.sf.isDomain(domain, self.opts['_internettlds']):
                    evt = SpiderFootEvent('DOMAIN_NAME', domain, self.__name__, event)
                    self.notifyListeners(evt)
                continue

            if self.cohostcount < self.opts['maxcohost']:
                if self.opts["verify"] and not self.sf.validateIP(domain, eventData):
                    self.debug("Host no longer resolves to our IP.")
                    continue

                if not self.opts["cohostsamedomain"]:
                    if self.getTarget().matches(domain, includeParents=True):
                        self.debug(
                            "Skipping " + domain + " because it is on the same domain."
                        )
                        continue

                evt = SpiderFootEvent("CO_HOSTED_SITE", domain, self.__name__, event)
                self.notifyListeners(evt)
                self.cohostcount += 1

    def isFreshEnough(self, result):
        limit = self.opts["age_limit_days"]
        if limit <= 0:
            return True

        timestamp = result.get("@timestamp")
        if timestamp is None:
            self.debug("Record doesn't have timestamp defined")
            return False

        last_dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
        last_ts = int(time.mktime(last_dt.timetuple()))
        age_limit_ts = int(time.time()) - (86400 * limit)

        if last_ts < age_limit_ts:
            self.debug("Record found but too old, skipping.")
            return False

        return True

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        sentData = set()

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error("You enabled sfp_onyphe, but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug("Skipping " + eventData + " as already mapped.")
            return

        self.results[eventData] = True

        geoLocDataArr = self.query("geoloc", eventData)

        if geoLocDataArr is not None:
            evt = SpiderFootEvent(
                "RAW_RIR_DATA", str(geoLocDataArr), self.__name__, event
            )
            self.notifyListeners(evt)

            for geoLocData in geoLocDataArr:
                if self.checkForStop():
                    return

                for result in geoLocData["results"]:
                    if not self.isFreshEnough(result):
                        continue

                    location = ", ".join(
                        [
                            _f
                            for _f in [
                                result.get("city"),
                                result.get("country"),
                            ]
                            if _f
                        ]
                    )
                    self.info("Found GeoIP for " + eventData + ": " + location)

                    if location in sentData:
                        self.debug(f"Skipping {location}, already sent")
                        continue

                    sentData.add(location)

                    evt = SpiderFootEvent("GEOINFO", location, self.__name__, event)
                    self.notifyListeners(evt)

                    coordinates = result.get("location")
                    if coordinates is None:
                        continue

                    if coordinates in sentData:
                        self.debug(f"Skipping {coordinates}, already sent")
                        continue
                    sentData.add(coordinates)

                    self.emitLocationEvent(coordinates, eventData, event)

                    self.emitDomainData(result, eventData, event)

        pastriesDataArr = self.query("pastries", eventData)

        if pastriesDataArr is not None:
            evt = SpiderFootEvent(
                "RAW_RIR_DATA", str(pastriesDataArr), self.__name__, event
            )
            self.notifyListeners(evt)

            for pastriesData in pastriesDataArr:
                if self.checkForStop():
                    return

                for result in pastriesData["results"]:
                    pastry = result.get("content")
                    if pastry is None:
                        continue

                    if pastry in sentData:
                        self.debug(f"Skipping {pastry}, already sent")
                        continue
                    sentData.add(pastry)

                    if not self.isFreshEnough(result):
                        continue

                    evt = SpiderFootEvent(
                        "LEAKSITE_CONTENT", pastry, self.__name__, event
                    )
                    self.notifyListeners(evt)

        threatListDataArr = self.query("threatlist", eventData)

        if threatListDataArr is not None:
            evt = SpiderFootEvent(
                "RAW_RIR_DATA", str(threatListDataArr), self.__name__, event
            )
            self.notifyListeners(evt)

            for threatListData in threatListDataArr:
                if self.checkForStop():
                    return

                for result in threatListData["results"]:
                    threatList = result.get("threatlist")

                    if threatList is None:
                        continue

                    if threatList in sentData:
                        self.debug(f"Skipping {threatList}, already sent")
                        continue
                    sentData.add(threatList)

                    if not self.isFreshEnough(result):
                        continue

                    evt = SpiderFootEvent(
                        "MALICIOUS_IPADDR",
                        result.get("threatlist"),
                        self.__name__,
                        event,
                    )
                    self.notifyListeners(evt)

        vulnerabilityDataArr = self.query("vulnscan", eventData)

        if vulnerabilityDataArr is not None:
            evt = SpiderFootEvent(
                "RAW_RIR_DATA", str(vulnerabilityDataArr), self.__name__, event
            )
            self.notifyListeners(evt)

            for vulnerabilityData in vulnerabilityDataArr:
                if self.checkForStop():
                    return

                for result in vulnerabilityData["results"]:
                    if not self.isFreshEnough(result):
                        continue

                    cves = result.get("cve")

                    if cves is None:
                        continue

                    for cve in cves:
                        if not cve:
                            continue

                        if cve in sentData:
                            continue
                        sentData.add(cve)

                        etype, cvetext = self.sf.cveInfo(cve)
                        evt = SpiderFootEvent(
                            etype,
                            cvetext,
                            self.__name__,
                            event,
                        )
                        self.notifyListeners(evt)

# End of sfp_onyphe class
