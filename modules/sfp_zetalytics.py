# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_zetalytics
# Purpose:      Query Zetalytics database for hostname & subdomain information
#
# Author:      Leo Trubach <leotrubach@gmail.com>
#
# Created:     2020-04-21
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from urllib.parse import urlencode

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_zetalytics(SpiderFootPlugin):
    BASE_URL = "https://zonecruncher.com/api/v1"
    meta = {
        "name": "Zetalytics",
        "summary": "Query the Zetalytics database for hosts on your target domain(s).",
        'flags': ["apikey"],
        "useCases": ["Passive"],
        "categories": ["Passive DNS"],
        "dataSource": {
            "website": "https://zetalytics.com/",
            "model": "FREE_AUTH_LIMITED",
            "references": ["https://zonecruncher.com/api-v1-docs/"],
            "apiKeyInstructions": [
                "Visit https://mailchi.mp/zetalytics/trial-access-request",
                "Register a free account and request an API key",
            ],
            "favIcon": "https://zetalytics.com/favicon.ico",
            "logo": "https://zetalytics.com/assets/images/logo.png",
            "description": "Zetalytics database provides several useful endpoints to perform passive DNS analysis",
        },
    }

    opts = {"api_key": "", "verify": True}

    optdescs = {
        "api_key": "Zetalytics API Key.",
        "verify": "Verify that any hostnames found on the target domain still resolve?",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=None):
        self.sf = sfc
        self.results = self.tempStorage()
        if userOpts:
            self.opts.update(userOpts)

    def watchedEvents(self):
        return ["INTERNET_NAME", "DOMAIN_NAME", "EMAILADDR"]

    def producedEvents(self):
        return ["INTERNET_NAME", "AFFILIATE_DOMAIN_NAME", "INTERNET_NAME_UNRESOLVED"]

    def emit(self, etype, data, pevent):
        if self.checkForStop():
            return None
        evt = SpiderFootEvent(etype, data, self.__name__, pevent)
        self.notifyListeners(evt)
        return evt

    def verify_emit_internet_name(self, hostname, pevent):
        if f"INTERNET_NAME:{hostname}" in self.results:
            return False

        if not self.getTarget().matches(hostname):
            return False

        if self.opts["verify"] and not self.sf.resolveHost(hostname) and not self.sf.resolveHost6(hostname):
            self.debug(f"Host {hostname} could not be resolved")
            self.emit("INTERNET_NAME_UNRESOLVED", hostname, pevent)
            return True

        self.emit("INTERNET_NAME", hostname, pevent)
        if self.sf.isDomain(hostname, self.opts["_internettlds"]):
            self.emit("DOMAIN_NAME", hostname, pevent)

        return True

    def request(self, path, params):
        params = {**params, "token": self.opts["api_key"]}
        qs = urlencode(params)
        res = self.sf.fetchUrl(
            f"{self.BASE_URL}{path}/?{qs}",
            timeout=self.opts["_fetchtimeout"],
            useragent="SpiderFoot",
        )

        if res["content"] is None:
            self.info(f"No Zetalytics info found for {path}?{qs}")
            return None

        try:
            return json.loads(res["content"])
        except Exception as e:
            self.error(f"Error processing JSON response from Zetalytics: {e}")
        return None

    def query_subdomains(self, domain):
        return self.request("/subdomains", {"q": domain})

    def query_hostname(self, hostname):
        return self.request("/hostname", {"q": hostname})

    def query_email_domain(self, email_domain):
        return self.request("/email_domain", {"q": email_domain})

    def query_email_address(self, email_address):
        return self.request("/email_address", {"q": email_address})

    def generate_subdomains_events(self, data, pevent):
        if not isinstance(data, dict):
            return False

        results = data.get("results", [])
        if not isinstance(results, list):
            return False

        events_generated = False
        for r in results:
            qname = r.get("qname")
            if not isinstance(qname, str):
                continue
            if self.verify_emit_internet_name(qname, pevent):
                events_generated = True

        return events_generated

    def generate_hostname_events(self, data, pevent):
        events_generated = False
        hostnames = set()
        if isinstance(data, dict):
            results = data.get("results")
            if isinstance("results", list):
                for r in results:
                    qname = r.get("qname")
                    if isinstance("qname", str):
                        hostnames.add(qname)
        for hostname in hostnames:
            if self.verify_emit_internet_name(hostname, pevent):
                events_generated = True
        return events_generated

    def generate_email_events(self, data, pevent):
        events_generated = False
        if isinstance(data, dict):
            results = data.get("results")
            if isinstance(results, list):
                for r in results:
                    domain = r.get("d")
                    if isinstance(domain, str):
                        self.emit("AFFILIATE_DOMAIN_NAME", domain, pevent)
                        events_generated = True
        return events_generated

    def generate_email_domain_events(self, data, pevent):
        events_generated = False
        if isinstance(data, dict):
            results = data.get("results")
            if isinstance(results, list):
                for r in results:
                    domain = r.get("d")
                    if isinstance(domain, str):
                        self.emit("AFFILIATE_DOMAIN_NAME", domain, pevent)
                        events_generated = True
        return events_generated

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        if self.checkForStop():
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        if f"{eventName}:{eventData}" in self.results:
            self.debug(f"Skipping {eventName}:{eventData}, already checked.")
            return
        self.results[f"{eventName}:{eventData}"] = True

        if eventName == "INTERNET_NAME":
            data = self.query_hostname(eventData)
            if self.generate_hostname_events(data, event):
                self.emit("RAW_RIR_DATA", json.dumps(data), event)

        elif eventName == "DOMAIN_NAME":
            data = self.query_subdomains(eventData)
            if self.generate_subdomains_events(data, event):
                self.emit("RAW_RIR_DATA", json.dumps(data), event)

            data = self.query_email_domain(eventData)
            if self.generate_email_domain_events(data, event):
                self.emit("RAW_RIR_DATA", json.dumps(data), event)

        elif eventName == "EMAILADDR":
            data = self.query_email_address(eventData)
            if self.generate_email_events(data, event):
                self.emit("RAW_RIR_DATA", json.dumps(data), event)
