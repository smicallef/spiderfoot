# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_subdomain_takeover
# Purpose:     Check if affiliated subdomains are vulnerable to takeover
#              using the fingerprints.json list from subjack by haccer:
#              - https://github.com/haccer/subjack/master/fingerprints.json
#
# Author:      <bcoles@gmail.com>
#
# Created:     2020-06-21
# Copyright:   (c) bcoles 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import time
import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_subdomain_takeover(SpiderFootPlugin):
    """Subdomain Takeover:Footprint,Investigate:Crawling and Scanning::Check if affiliated subdomains are vulnerable to takeover."""

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None
    errorState = False
    fingerprints = dict()

    # Initialize module and module options
    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        content = self.sf.cacheGet("subjack-fingerprints", 48)
        if content is None:
            url = "https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json"
            res = self.sf.fetchUrl(url, useragent="SpiderFoot")

            if res['content'] is None:
                self.sf.error("Unable to fetch %s" % url, False)
                self.errorState = True
                return None

            self.sf.cachePut("subjack-fingerprints", res['content'])
            content = res['content']

        try:
            self.fingerprints = json.loads(content)
        except Exception as e:
            self.sf.error("Unable to parse subdomain takeover fingerprints list.", False)
            self.errorState = True
            return None

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["AFFILIATE_INTERNET_NAME", "AFFILIATE_INTERNET_NAME_UNRESOLVED"]

    # What events this module produces
    def producedEvents(self):
        return ["AFFILIATE_INTERNET_NAME_HIJACKABLE"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if eventData in self.results:
            return None

        self.results[eventData] = True

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if eventName == "AFFILIATE_INTERNET_NAME":
            for data in self.fingerprints:
                service = data.get("service")
                cnames = data.get("cname")
                fingerprints = data.get("fingerprint")
                nxdomain = data.get("nxdomain")

                if nxdomain:
                    continue

                for cname in cnames:
                    if not cname.lower() in eventData.lower():
                        continue

                    for proto in ["https", "http"]:
                        res = self.sf.fetchUrl(
                            "%s://%s/" % (proto, eventData),
                            timeout=15,
                            useragent=self.opts['_useragent'],
                            verify=False
                        )
                        if not res:
                            continue
                        if not res['content']:
                            continue
                        for fingerprint in fingerprints:
                            if fingerprint in res['content']:
                                self.sf.info("%s appears to be vulnerable to takeover on %s" % (eventData, service))
                                evt = SpiderFootEvent("AFFILIATE_INTERNET_NAME_HIJACKABLE", eventData, self.__name__, event)
                                self.notifyListeners(evt)
                                break

            return None

        if eventName == "AFFILIATE_INTERNET_NAME_UNRESOLVED":
            for data in self.fingerprints:
                service = data.get("service")
                cnames = data.get("cname")
                nxdomain = data.get("nxdomain")

                if not nxdomain:
                    continue

                for cname in cnames:
                    if not cname.lower() in eventData.lower():
                        continue
                    self.sf.info("%s appears to be vulnerable to takeover on %s" % (eventData, service))
                    evt = SpiderFootEvent("AFFILIATE_INTERNET_NAME_HIJACKABLE", eventData, self.__name__, event)
                    self.notifyListeners(evt)

            return None

# End of sfp_subdomain_takeover class
