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
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_robtex(SpiderFootPlugin):
    """Robtex:Footprint,Investigate,Passive:Networking:errorprone:Search Robtex.com for hosts sharing the same IP."""

    # Default options
    opts = {
        'cohostsamedomain': False,
        'verify': True
    }

    # Option descriptions
    optdescs = {
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP."
    }

    results = list()

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
        return ["CO_HOSTED_SITE", "SEARCH_ENGINE_WEB_CONTENT"]

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

            res = self.sf.fetchUrl("https://www.robtex.com/?a=2&ip=" + ip + "&shared=1",
                                   useragent=self.opts['_useragent'],
                                   timeout=self.opts['_fetchtimeout'])
            if res['content'] is None:
                self.sf.error("Unable to fetch robtex content.", False)
                continue

            if "shared DNS of" in res['content'] or "Pointing to " in res['content']:
                p = re.compile("<li><a href=(.*?/dns-lookup/.*?)..>(.[^<]*)", re.IGNORECASE)
                matches = p.findall(res['content'])
                for mt in matches:
                    m = mt[1]
                    self.sf.info("Found something on same IP: " + m)
                    if not self.opts['cohostsamedomain']:
                        if self.getTarget().matches(m, includeParents=True):
                            self.sf.debug("Skipping " + m + " because it is on the same domain.")
                            continue

                    if '*' in m:
                        self.sf.debug("Skipping wildcard name: " + m)
                        continue

                    if '.' not in m:
                        self.sf.debug("Skipping tld: " + m)
                        continue

                    if m not in myres and m != ip:
                        if self.opts['verify'] and not self.validateIP(m, ip):
                            self.sf.debug("Host no longer resolves to our IP.")
                            continue
                        evt = SpiderFootEvent("CO_HOSTED_SITE", m.lower(), self.__name__, event)
                        self.notifyListeners(evt)
                        myres.append(m.lower())

            # Submit the bing results for analysis
            evt = SpiderFootEvent("SEARCH_ENGINE_WEB_CONTENT", results[key],
                                  self.__name__, event)
            self.notifyListeners(evt)

        # End of sfp_robtex class
