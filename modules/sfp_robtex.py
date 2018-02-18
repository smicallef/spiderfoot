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
import time
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_robtex(SpiderFootPlugin):
    """Robtex:Footprint,Investigate,Passive:Passive DNS:errorprone:Search Robtex.com for hosts sharing the same IP."""


    # Default options
    opts = {
        'verify': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24,
        'cohostsamedomain': False
    }

    # Option descriptions
    optdescs = {
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible co-hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for identifying co-hosts?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?"
    }

    results = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER", "NETBLOCK_MEMBER"]

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

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return None
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxsubnet']:
                    self.sf.debug("Network size bigger than permitted: " +
                                  str(IPNetwork(eventData).prefixlen) + " > " +
                                  str(self.opts['maxsubnet']))
                    return None

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results.append(str(ipaddr))
        else:
            qrylist.append(eventData)
            self.results.append(eventData)

        myres = list()

        for ip in qrylist:
            if self.checkForStop():
                return None

            retry = 0
            while retry < 2:
                res = self.sf.fetchUrl("https://freeapi.robtex.com/ipquery/" + ip,
                                   timeout=self.opts['_fetchtimeout'])
                if res['code'] == "200":
                    break
                if res['code'] == "404":
                    return None
                if res['code'] == "429":
                    # Back off a little further
                    time.sleep(2)
                retry += 1

            if res['content'] is None:
                self.sf.error("Unable to query robtex API.", False)
                retry += 1
                continue

            try:
                data = json.loads(res['content'])
            except BaseException as e:
                self.sf.error("Error parsing JSON from robtex API.", False)
                return None

            if len(data.get('pas')) > 0:
                for r in data.get('pas'):
                    if 'o' not in r:
                        continue
                    if not self.opts['cohostsamedomain']:
                        if self.getTarget().matches(r['o'], includeParents=True):
                            self.sf.debug("Skipping " + r['o'] + " because it is on the same domain.")
                            continue

                    if self.opts['verify'] and not self.validateIP(r['o'], ip):
                        self.sf.debug("Host no longer resolves to our IP.")
                        continue
                    evt = SpiderFootEvent("CO_HOSTED_SITE", r['o'], self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_robtex class
