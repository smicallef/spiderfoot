# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_hostio
# Purpose:      Host.io database query module
#
# Author:      Lev Trubach <leotrubach@gmail.com>
#
# Created:     2020-08-21
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------
import json

from sflib import SpiderFootPlugin, SpiderFootEvent


class sfp_hostio(SpiderFootPlugin):
    """Host.io Query Module:Passive:Passive DNS:apikey:Obtain DNS information from host.io source."""

    meta = {
        "name": "Host.io Query Module",
        "summary": "Obtain DNS information from host.io source.",
        "flags": ["apikey"],
        "useCases": ["Passive"],
        "categories": ["Passive DNS"],
        "dataSource": {
            "website": "https://host.io",
            "model": "FREE_AUTH_LIMITED",
            "references": ["https://host.io/docs"],
            "apiKeyInstructions": [
                "Visit https://host.io/signup",
                "Register a free account",
                "Visit https://host.io/dashboard and use the authentication token provided",
            ],
            "favIcon": "https://host.io/static/images/hostio/favicon.png?v2",
            "logo": "https://host.io/static/images/hostio/favicon.png?v2",  # Seems like they embed it as SVG
            "description": "We collect data on every known domain name, from every TLD, and update it every month. "
            "Our data includes DNS records and website data for each of the domains."
            "We process terabytes of data and summarize it to produce our final results. "
            "Browse through our site to see backlinks, redirects, server details or IP address "
            "and hosting provider details courtesy of IPinfo.io.",
        },
    }

    opts = {
        "api_key": "",
        "checkcohosts": True,
        "checkaffiliates": True,
        "maxcohost": 100,
        "verify": True,
    }

    optdescs = {
        "api_key": "Host.io API Key.",
        "checkcohosts": "Check co-hosted sites?",
        "checkaffiliates": "Check affiliates?",
        "maxcohost": "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        "verify": "Verify that any hostnames found on the target domain still resolve?",
    }

    errorState = False

    def setup(self, sfc, userOpts=None):
        if userOpts is None:
            userOpts = {}
        self.sf = sfc
        self.results = self.tempStorage()
        self.opts.update(userOpts)

    def watchedEvents(self):
        return [
            "AFFILIATE_DOMAIN_NAME",
            "CO_HOSTED_SITE_DOMAIN",
            "DOMAIN_NAME",
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            "IP_ADDRESS",
            "COUNTRY_NAME"
        ]

    # When querying third parties, it's best to have a dedicated function
    # to do so and avoid putting it in handleEvent()
    def handle_error_response(self, qry, res):
        try:
            error_info = json.loads(res["content"])
        except Exception as e:
            error_info = None
        if error_info:
            error_message = error_info.get("error")
        else:
            error_message = None
        if error_message:
            error_str = f", message {error_message}"
        else:
            error_str = ""
        self.sf.info(f"Failed to get results for {qry}, code {res['code']}{error_str}")

    def query(self, qry):
        res = self.sf.fetchUrl(
            f"https://host.io/api/full/{qry}",
            headers={"Authorization": f"Bearer {self.opts['api_key']}"},
            timeout=self.opts["_fetchtimeout"],
            useragent="SpiderFoot",
        )
        if res["code"] != '200':
            self.handle_error_response(qry, res)
            return None

        if res["content"] is None:
            self.sf.info(f"No Host.io info found for {qry}")
            return None

        try:
            info = json.loads(res["content"])
        except Exception as e:
            self.sf.error("Error processing JSON response from Host.io.", False)
            return None

        return info

    def is_my_event(self, event):
        if event.eventType == 'COHOSTED_SITE_DOMAIN':
            if not self.opts["checkcohosts"]:
                return False
        elif event.eventType == "AFFILIATE_DOMAIN_NAME":
            if not self.opts["checkaffiliates"]:
                return False
        return True

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.sf.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!",
                False,
            )
            self.errorState = True
            return None

        if not self.is_my_event(event):
            return None

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData} as already mapped.")
            return None
        self.results[eventData] = True

        data = self.query(event.data)
        if not data:
            self.sf.error(f"No data received for {event.data}", False)
            return None

        ipinfo = data.get("ipinfo")
        if ipinfo is None:
            self.sf.error(f"No 'ipinfo' key present in response", False)
            return None

        for address, ip_data in data["ipinfo"].items():
            evt = SpiderFootEvent('IP_ADDRESS', address, self.__name__, event)
            self.notifyListeners(evt)

            country = ip_data.get("country")
            if country is not None:
                country_evt = SpiderFootEvent("COUNTRY_NAME", country, self.__name__, evt)
                self.notifyListeners(country_evt)

        evt = SpiderFootEvent("RAW_RIR_DATA", json.dumps(data), self.__name__, event)
        self.notifyListeners(evt)