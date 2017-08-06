# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_hackertarget
# Purpose:      Searches Hackertarget.com for hosts sharing the same IP.
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


class sfp_hackertarget(SpiderFootPlugin):
    """HackerTarget.com:Footprint,Investigate,Passive:Reputation Systems:errorprone:Search HackerTarget.com for hosts sharing the same IP."""


    # Default options
    opts = {
        'cohostsamedomain': False,
        'verify': True,
        'netblocklookup': True,
        'maxnetblock': 24
    }

    # Option descriptions
    optdescs = {
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
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

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return None
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                    self.sf.debug("Network size bigger than permitted: " +
                                  str(IPNetwork(eventData).prefixlen) + " > " +
                                  str(self.opts['maxnetblock']))
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

            res = self.sf.fetchUrl("http://api.hackertarget.com/reverseiplookup/?q=" + eventData,
                                   useragent=self.opts['_useragent'],
                                   timeout=self.opts['_fetchtimeout'])
            if res['content'] is None:
                self.sf.error("Unable to fetch hackertarget.com content.", False)
                continue

            if "No records" not in res['content']:
                hosts = res['content'].split('\n')
                for h in hosts:
                    if " " in h:
                        continue
                    self.sf.info("Found something on same IP: " + h)
                    if not self.opts['cohostsamedomain']:
                        if self.getTarget().matches(h, includeParents=True):
                            self.sf.debug("Skipping " + h + " because it is on the same domain.")
                            continue

                    if h not in myres and h != ip:
                        if self.opts['verify'] and not self.validateIP(h, ip):
                            self.sf.debug("Host no longer resolves to our IP.")
                            continue
                        evt = SpiderFootEvent("CO_HOSTED_SITE", h.lower(), self.__name__, event)
                        self.notifyListeners(evt)
                        myres.append(h.lower())

# End of sfp_hackertarget class
