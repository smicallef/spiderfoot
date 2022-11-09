# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_greynoise_community
# Purpose:      Query GreyNoise's Community API
#
# Author:       Brad Chiappetta, GreyNoise
# Updated By:   Brad Chiappetta, GreyNoise
#
# Created:      31-Aug-2022
# Updated:      31-Aug-2022
# Copyright:    (c) Steve Micallef
# Licence:      MIT
# -------------------------------------------------------------------------------

import json
import time
from datetime import datetime

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_greynoise_community(SpiderFootPlugin):

    meta = {
        "name": "GreyNoise Community",
        "summary": "Obtain IP enrichment data from GreyNoise Community API",
        "flags": ["apikey"],
        "useCases": ["Investigate", "Passive"],
        "categories": ["Reputation Systems"],
        "dataSource": {
            "website": "https://greynoise.io/",
            "model": "FREE_AUTH_LIMITED",
            "references": ["https://docs.greynoise.io/reference/get_v3-community-ip", "https://viz.greynoise.io/signup"],
            "apiKeyInstructions": [
                "Visit https://viz.greynoise.io/signup",
                "Sign up for a free account",
                "Navigate to https://viz.greynoise.io/account/",
                "The API key is listed under 'API Key'",
            ],
            "favIcon": "https://viz.greynoise.io/favicon.ico",
            "logo": "https://viz.greynoise.io/_nuxt/img/greynoise-logo.dccd59d.png",
            "description": "At GreyNoise, we collect and analyze untargeted, widespread, "
            "and opportunistic scan and attack activity that reaches every server directly connected to the Internet. "
            "Mass scanners (such as Shodan and Censys), search engines, bots, worms, "
            "and crawlers generate logs and events omnidirectionally on every IP address in the IPv4 space. "
            "GreyNoise gives you the ability to filter this useless noise out.",
        },
    }

    # Default options
    opts = {
        "api_key": "",
        "age_limit_days": 30,
    }

    # Option descriptions
    optdescs = {
        "api_key": "GreyNoise Community API Key.",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "NETBLOCK_MEMBER", "NETBLOCK_OWNER"]

    # What events this module produces
    def producedEvents(self):
        return [
            "MALICIOUS_IPADDR",
            "COMPANY_NAME",
            "RAW_RIR_DATA",
        ]

    def queryIP(self, qry, qry_type):
        gn_community_url = "https://api.greynoise.io/v3/community/"

        headers = {"key": self.opts["api_key"]}
        res = {}
        if qry_type == "ip":
            self.debug(f"Querying GreyNoise Community API for IP: {qry}")
            ip_res = {}
            ip_response = self.sf.fetchUrl(
                gn_community_url + qry,
                timeout=self.opts["_fetchtimeout"],
                useragent="greynoise-spiderfoot-community-v1.2.0",
                headers=headers,
            )
            if ip_response["code"] == "200":
                ip_res = json.loads(ip_response["content"])
                res = ip_res

        if not res:
            self.error("Greynoise API key seems to have been rejected or you have exceeded usage limits.")
            self.errorState = True
            return None

        return res

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error("You enabled sfp_greynoise_community but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "IP_ADDRESS":
            evtType = "MALICIOUS_IPADDR"
            qryType = "ip"
        if eventName == "AFFILIATE_IPADDR":
            evtType = "MALICIOUS_AFFILIATE_IPADDR"
            qryType = "ip"

        ret = self.queryIP(eventData, qryType)

        if not ret:
            return

        if "data" not in ret and "noise" not in ret:
            return

        if "noise" in ret:
            if ret.get("noise", None):
                lastseen = ret.get("last_seen", "1970-01-01")
                lastseen_dt = datetime.strptime(lastseen, "%Y-%m-%d")
                lastseen_ts = int(time.mktime(lastseen_dt.timetuple()))
                age_limit_ts = int(time.time()) - (86400 * self.opts["age_limit_days"])
                if self.opts["age_limit_days"] > 0 and lastseen_ts < age_limit_ts:
                    self.debug("Record found but too old, skipping.")
                    return
                e = SpiderFootEvent("RAW_RIR_DATA", str(ret), self.__name__, event)
                self.notifyListeners(e)

                # Only report meta data about the target, not affiliates
                if ret.get("name", "unknown") != "unknown":
                    e = SpiderFootEvent("COMPANY_NAME", ret.get("name"), self.__name__, event)
                    self.notifyListeners(e)

                if ret.get("classification"):
                    descr = (
                        "GreyNoise - Mass-Scanning IP Detected ["
                        + eventData
                        + "]\n - Classification: "
                        + ret.get("classification")
                    )
                    descr += "\n<SFURL>https://viz.greynoise.io/ip/" + ret.get("ip") + "</SFURL>"
                    e = SpiderFootEvent(evtType, descr, self.__name__, event)
                    self.notifyListeners(e)

# End of sfp_greynoise_community class
