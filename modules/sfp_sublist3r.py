# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_sublist3r
# Purpose:      SpiderFoot plug-in for subdomain enumeration using
#               api.sublist3r.com
#
# Author:      TheTechromancer
#
# Created:     05/21/2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_sublist3r(SpiderFootPlugin):

    meta = {
        "name": "Sublist3r PassiveDNS",
        "summary": "Passive subdomain enumeration using Sublist3r's API",
        "useCases": ["Investigate", "Footprint", "Passive"],
        "categories": ["Passive DNS"],
        "dataSource": {
            "website": "https://api.sublist3r.com",
            "model": "FREE_NOAUTH_UNLIMITED",
            "description": "This is the API queried by the Sublist3r tool.",
        }
    }

    # Default options
    opts = {}

    # Option descriptions
    optdescs = {}

    def setup(self, sfc, userOpts=dict()):

        self.sf = sfc
        self.sf.debug("Setting up sfp_sublist3r")
        self.state = self.tempStorage()
        self.state.update({
            "events": [],
        })
        self.__dataSource__ = "DNS"

        self.opts.update(userOpts)

    def watchedEvents(self):

        return ["DOMAIN_NAME"]

    def producedEvents(self):

        return ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]

    def query(self, domain):

        url = f"https://api.sublist3r.com/search.php?domain={domain}"
        ret = []
        res = self.sf.fetchUrl(
            url,
            useragent=self.opts.get("_useragent", "Spiderfoot"),
            # mirror sublist3r's headers
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.8",
                "Accept-Encoding": "gzip",
            }
        )
        try:
            ret = [s.strip().lower() for s in json.loads(res["content"])]
        except json.decoder.JSONDecodeError as e:
            self.sf.error(f"Error decoding JSON response: {e}")
        except TypeError:
            self.sf.error("Error querying Sublist3r API")

        if res["code"] not in ["200"]:
            self.sf.error(f"Bad response code \"{res['code']}\" from Sublist3r API")

        return list(set(ret))

    def sendEvent(self, source, host):

        if self.sf.resolveHost(host):
            e = SpiderFootEvent("INTERNET_NAME", host, self.__name__, source)
        else:
            e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, source)
        self.notifyListeners(e)

    def handleEvent(self, event):

        domain = str(event.data).lower()

        self.sf.debug(f"Received event, {event.eventType}, from {event.module}")

        # skip if we've already processed this event
        eventDataHash = self.sf.hashstring(event.data)
        if eventDataHash in self.state["events"]:
            self.sf.debug(f"Skipping already-processed event, {event.eventType}, from {event.module}")
            return
        self.state["events"].append(eventDataHash)

        for hostname in self.query(domain):
            if hostname.endswith(domain) and not hostname == domain:
                self.sendEvent(event, hostname)
            else:
                self.sf.debug(f"Invalid subdomain: {hostname}")
