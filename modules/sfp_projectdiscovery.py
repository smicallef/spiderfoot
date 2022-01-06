# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_projectdiscovery
# Purpose:      Search for hosts/subdomains using chaos.projectdiscovery.io
#
# Author:      Filip Aleksić <faleksicdev@gmail.com>
#
# Created:     2020-09-04
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_projectdiscovery(SpiderFootPlugin):
    meta = {
        "name": "ProjectDiscovery Chaos",
        "summary": "Search for hosts/subdomains using chaos.projectdiscovery.io",
        'flags': ["apikey"],
        "useCases": ["Passive", "Footprint", "Investigate"],
        "categories": ["Passive DNS"],
        "dataSource": {
            "website": "https://chaos.projectdiscovery.io",
            "model": "PRIVATE_ONLY",
            "references": [
                "https://chaos.projectdiscovery.io/#/docs",
                "https://projectdiscovery.io/privacy",
                "https://projectdiscovery.io/about",
            ],
            "apiKeyInstructions": [
                "Visit https://chaos.projectdiscovery.io/#/",
                "Click the request access button",
                "Click the 'Early signup form' link or go to https://forms.gle/GP5nTamxJPfiMaBn9",
                "Click on 'Developer'",
                "The API key is listed under 'Your API Key'",
                "You will receive your API key by email.",
            ],
            "logo": "https://projectdiscovery.io/assets/img/logo.png",
            "description": "Projectdiscovery Chaos actively collect and maintain "
            "internet-wide assets' data, this project is meant to "
            "enhance research and analyse changes around DNS for better insights. ",
        },
    }

    opts = {
        "api_key": "",
        "verify": True,
    }
    optdescs = {
        "api_key": "chaos.projectdiscovery.io API Key.",
        "verify": "Verify that any hostnames found on the target domain still resolve?",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["DOMAIN_NAME"]

    def producedEvents(self):
        return ["RAW_RIR_DATA", "INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]

    def query(self, qry):
        headers = {"Accept": "application/json", "Authorization": self.opts["api_key"]}
        res = self.sf.fetchUrl(
            f"https://dns.projectdiscovery.io/dns/{qry}/subdomains",
            timeout=self.opts["_fetchtimeout"],
            useragent="SpiderFoot",
            headers=headers,
        )

        if res["content"] is None:
            self.info("No DNS info found in chaos projectdiscovery API for " + qry)
            return None

        try:
            return json.loads(res["content"])
        except json.JSONDecodeError as e:
            self.error(
                f"Error processing JSON response from Chaos projectdiscovery: {e}"
            )

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error(
                "You enabled sfp_projectdiscovery but did not set an API key!"
            )
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName not in self.watchedEvents():
            return

        result = self.query(eventData)
        if result is None:
            return

        subdomains = result.get("subdomains")
        if not isinstance(subdomains, list):
            return

        evt = SpiderFootEvent("RAW_RIR_DATA", str(result), self.__name__, event)
        self.notifyListeners(evt)

        resultsSet = set()
        for subdomain in subdomains:
            if self.checkForStop():
                return

            if subdomain in resultsSet:
                continue
            completeSubdomain = f"{subdomain}.{eventData}"
            if self.opts["verify"] and not self.sf.resolveHost(completeSubdomain) and not self.sf.resolveHost6(completeSubdomain):
                self.debug(f"Host {completeSubdomain} could not be resolved")
                evt = SpiderFootEvent(
                    "INTERNET_NAME_UNRESOLVED", completeSubdomain, self.__name__, event
                )
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent(
                    "INTERNET_NAME", completeSubdomain, self.__name__, event
                )
                self.notifyListeners(evt)

            resultsSet.add(subdomain)

# End of sfp_projectdiscovery class
