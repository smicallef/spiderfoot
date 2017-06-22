# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_robtex
# Purpose:      Searches Robtex.com for hosts sharing the same IP.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import socket
import json
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_robtex(SpiderFootPlugin):
    """Robtex:Footprint,Investigate,Passive:Networking:errorprone:Search Robtex.com for hosts sharing the same IP."""

    # Default options
    opts = {
        'cohostsamedomain': False,
        'verify': True,
        'api_key': ""
    }

    # Option descriptions
    optdescs = {
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        'api_key': "Robtex.com requires an API key, obtained from the Mashape.com marketplace."
    }

    results = list()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["CO_HOSTED_SITE"]

    def validateIP(self, host, ip):
        try:
            addrs = socket.gethostbyname_ex(host)
        except BaseException as e:
            self.sf.debug("Unable to resolve " + host + ": " + str(e))
            return False

        for addr in addrs:
            if type(addr) == list:
                for a in addr:
                    if str(a) == ip:
                        return True
            else:
                if str(addr) == ip:
                    return True
        return False

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.errorState:
            return None

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_robtex but did not set an API key!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                if str(ipaddr) not in self.results:
                    qrylist.append(str(ipaddr))
                    self.results.append(str(ipaddr))
        else:
            qrylist.append(eventData)
            self.results.append(eventData)

        myres = list()

        for ip in qrylist:
            if self.checkForStop():
                return None

            res = self.sf.fetchUrl("https://robtex.p.mashape.com/reverse/?q=" + ip + "&m=100",
                                   useragent=self.opts['_useragent'],
                                   timeout=self.opts['_fetchtimeout'],
                                   headers={
                                    'X-Mashape-Key': self.opts['api_key'], 
                                    'Accept': 'application/json'}
                                  )
            if res['content'] is None:
                self.sf.error("Unable to fetch robtex content.", False)
                continue

            try:
                data = json.loads(res['content'])
            except BaseException as e:
                self.sf.error("Error parsing JSON from robtex API.", False)
                # Abort so that we don't use up API credits in case this is an error
                # on our side.
                self.errorState = True
                return None

            if len(data.get('l')) > 0:
                for r in data.get('l'):
                    if self.opts['verify'] and not self.validateIP(r['o'], ip):
                        self.sf.debug("Host no longer resolves to our IP.")
                        continue
                    evt = SpiderFootEvent("CO_HOSTED_SITE", r['o'], self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_robtex class
