# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_botscout
# Purpose:      SpiderFoot plug-in to search botsout.com using their API, for 
#               potential malicious IPs and e-mail addresses.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     25/07/2016
# Copyright:   (c) Steve Micallef 2016
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_botscout(SpiderFootPlugin):
    """BotScout:Investigate:Blacklists:apikey:Searches botscout.com's database of spam-bot IPs and e-mail addresses."""

    # Default options
    opts = {
        "apikey": ""
    }
    optdescs = {
        "apikey": "botscout.com API key. Without this you will be limited to 50 look-ups per day."
    }
    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS','EMAILADDR']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_EMAILADDR"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already searched.")
            return None
        else:
            self.results[eventData] = True

        if self.opts['apikey']:
            url = "http://botscout.com/test/?key=" + self.opts['apikey'] + "&all="
        else:
            url = "http://botscout.com/test/?all="

        res = self.sf.fetchUrl(url + eventData,
                               timeout=self.opts['_fetchtimeout'], 
                               useragent=self.opts['_useragent'])
        if res['content'] is None or "|" not in res['content']:
            self.sf.error("Error encountered processing " + eventData, False)
            return None

        if res['content'].startswith("Y|"):
            self.sf.info("Found Botscout entry for " + eventData + ": " + res['content'])
            if eventName == "IP_ADDRESS":
                t = "MALICIOUS_IPADDR"
            else:
                t = "MALICIOUS_EMAILADDR"

            evt = SpiderFootEvent(t, eventData, self.__name__, event)
            self.notifyListeners(evt)

            return None

# End of sfp_botscout class
