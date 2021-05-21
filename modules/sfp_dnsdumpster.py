# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_dnsdumpster
# Purpose:     SpiderFoot plug-in for subdomain enumeration using
#              dnsdumpster.com
#
# Author:      TheTechromancer
#
# Created:     05/21/2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from bs4 import BeautifulSoup

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_dnsdumpster(SpiderFootPlugin):

    meta = {
        "name": "DNSDumpster",
        "summary": "Passive subdomain enumeration using HackerTarget's DNSDumpster",
        "useCases": ["Investigate", "Footprint", "Passive"],
        "categories": ["Passive DNS"],
        "dataSource": {
            "website": "https://dnsdumpster.com/",
            "model": "FREE_NOAUTH_UNLIMITED",
            "description": "DNSdumpster.com is a FREE domain research tool that can discover hosts related to a domain.",
        }
    }

    # Default options
    opts = {}

    # Option descriptions
    optdescs = {}

    def setup(self, sfc, userOpts=dict()):

        self.sf = sfc
        self.sf.debug("Setting up sfp_dnsdumpster")
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

        ret = []

        # first, get the CSRF tokens
        url = "https://dnsdumpster.com"
        res1 = self.sf.fetchUrl(
            url,
            useragent=self.opts.get("_useragent", "Spiderfoot")
        )
        if res1["code"] not in ["200"]:
            self.sf.error(f"Bad response code \"{res1['code']}\" from DNSDumpster")
        else:
            self.sf.debug(f"Valid response code \"{res1['code']}\" from DNSDumpster")
        html = BeautifulSoup(str(res1["content"]), features="lxml")
        csrftoken = None
        csrfmiddlewaretoken = None
        try:
            for cookie in res1["headers"].get("set-cookie", "").split(";"):
                k, v = cookie.split('=', 1)
                if k == "csrftoken":
                    csrftoken = str(v)
            csrfmiddlewaretoken = html.find("input", {"name": "csrfmiddlewaretoken"}).attrs.get("value", None)
        except AttributeError:
            pass

        # Abort if we didn't get the tokens
        if not csrftoken or not csrfmiddlewaretoken:
            self.sf.error("Error obtaining CSRF tokens")
            self.errorState = True
            return ret
        else:
            self.sf.debug("Successfully obtained CSRF tokens")

        # Otherwise, do the needful
        url = "https://dnsdumpster.com/"
        subdomains = set()
        res2 = self.sf.fetchUrl(
            url,
            cookies={
                "csrftoken": csrftoken
            },
            postData={
                "csrfmiddlewaretoken": csrfmiddlewaretoken,
                "targetip": str(domain).lower()
            },
            headers={
                "origin": "https://dnsdumpster.com",
                "referer": "https://dnsdumpster.com/"
            },
            useragent=self.opts.get("_useragent", "Spiderfoot")
        )
        if res2["code"] not in ["200"]:
            self.sf.error(f"Bad response code \"{res2['code']}\" from DNSDumpster")
            return ret

        html = BeautifulSoup(str(res2["content"]), features="lxml")
        escaped_domain = re.escape(domain)
        match_pattern = re.compile(r"^[\w\.-]+\." + escaped_domain + r"$")
        for subdomain in html.findAll(text=match_pattern):
            subdomains.add(str(subdomain).strip().lower())

        return list(subdomains)

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
