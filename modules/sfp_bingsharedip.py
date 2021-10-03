# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_bingsharedip
# Purpose:      Searches Bing for hosts sharing the same IP.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_bingsharedip(SpiderFootPlugin):

    meta = {
        'name': "Bing (Shared IPs)",
        'summary': "Search Bing for hosts sharing the same IP.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.bing.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.microsoft.com/en-us/azure/cognitive-services/bing-web-search/"
            ],
            'apiKeyInstructions': [
                "Visit https://azure.microsoft.com/en-in/services/cognitive-services/bing-web-search-api/",
                "Register a free account",
                "Select on Bing Custom Search",
                "The API keys are listed under 'Key1' and 'Key2' (both should work)"
            ],
            'favIcon': "https://www.bing.com/sa/simg/bing_p_rr_teal_min.ico",
            'logo': "https://www.bing.com/sa/simg/bing_p_rr_teal_min.ico",
            'description': "The Bing Search APIs let you build web-connected apps and services that "
            "find webpages, images, news, locations, and more without advertisements.",
        }
    }

    # Default options
    opts = {
        "cohostsamedomain": False,
        "pages": 20,
        "verify": True,
        "maxcohost": 100,
        "api_key": ""
    }

    # Option descriptions
    optdescs = {
        "cohostsamedomain": "Treat co-hosted sites on the same target domain as co-hosting?",
        "pages": "Number of max bing results to request from API.",
        "verify": "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        "maxcohost": "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        "api_key": "Bing API Key for shared IP search."
    }

    results = None
    cohostcount = 0
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0
        self.__dataSource__ = "Bing"
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["CO_HOSTED_SITE", "IP_ADDRESS", "RAW_RIR_DATA"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "" and self.opts['api_key'] == "":
            self.error("You enabled sfp_bingsharedip but did not set a Bing API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        # Ignore IP addresses from myself as they are just for creating
        # a link from the netblock to the co-host.
        if eventName == "IP_ADDRESS" and srcModuleName == "sfp_bingsharedip":
            self.debug("Ignoring " + eventName + ", from self.")
            return

        if self.cohostcount > self.opts["maxcohost"]:
            return

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                if str(ipaddr) not in self.results:
                    qrylist.append(str(ipaddr))
                    self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)
            self.results[eventData] = True

        myres = list()

        for ip in qrylist:
            if self.checkForStop():
                return

            res = self.sf.bingIterate(
                searchString="ip:" + ip,
                opts={
                    "timeout": self.opts["_fetchtimeout"],
                    "useragent": self.opts["_useragent"],
                    "count": self.opts["pages"],
                    "api_key": self.opts["api_key"],
                },
            )
            if res is None:
                # Failed to talk to bing api or no results returned
                return

            urls = res["urls"]

            for url in urls:
                self.info("Found something on same IP: " + url)
                site = self.sf.urlFQDN(url.lower())
                if site not in myres and site != ip:
                    if not self.opts["cohostsamedomain"]:
                        if self.getTarget().matches(site, includeParents=True):
                            self.debug(
                                f"Skipping {site} because it is on the same domain."
                            )
                            continue
                    if self.opts["verify"] and not self.sf.validateIP(site, ip):
                        self.debug(f"Host {site} no longer resolves to {ip}")
                        continue
                    # Create an IP Address event stemming from the netblock as the
                    # link to the co-host.
                    if eventName == "NETBLOCK_OWNER":
                        ipe = SpiderFootEvent("IP_ADDRESS", ip, self.__name__, event)
                        self.notifyListeners(ipe)
                        evt = SpiderFootEvent(
                            "CO_HOSTED_SITE", site, self.__name__, ipe
                        )
                        self.notifyListeners(evt)
                    else:
                        evt = SpiderFootEvent(
                            "CO_HOSTED_SITE", site, self.__name__, event
                        )
                        self.notifyListeners(evt)
                    self.cohostcount += 1
                    myres.append(site)

            if urls:
                evt = SpiderFootEvent(
                    "RAW_RIR_DATA", str(res), self.__name__, event
                )
                self.notifyListeners(evt)

# End of sfp_bingsharedip class
