# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_torexits
# Purpose:      Checks if an IP address or netblock appears on the TOR exit node list.
#
# Author:       steve@binarypool.com
#
# Created:     14/12/2013
# Copyright:   (c) Steve Micallef, 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from netaddr import IPAddress, IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_torexits(SpiderFootPlugin):

    meta = {
        'name': "TOR Exit Nodes",
        'summary': "Check if an IP adddress or netblock appears on the torproject.org exit node list.",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Secondary Networks"]
    }

    # Default options
    opts = {
        'checkaffiliates': True,
        'cacheperiod': 18,
        'checknetblocks': True,
        'checksubnets': True
    }

    # Option descriptions
    optdescs = {
        'checkaffiliates': "Apply checks to affiliates?",
        'cacheperiod': "Hours to cache list data before re-fetching.",
        'checknetblocks': "Report if any malicious IPs are found within owned netblocks?",
        'checksubnets': "Check if any malicious IPs are found within the same subnet of the target?"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.__dataSource__ = "torproject.org"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "AFFILIATE_IPADDR",
            "NETBLOCK_MEMBER",
            "NETBLOCK_OWNER"
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_SUBNET",
            "MALICIOUS_NETBLOCK"
        ]

    def queryExitNodes(self, target, targetType):
        exit_addresses = self.retrieveExitNodes()

        if not exit_addresses:
            self.errorState = True
            return False

        if targetType == "ip":
            if target in exit_addresses:
                self.debug(f"IP address {target} found in TOR exit node list.")
                return True
        elif targetType == "netblock":
            netblock = IPNetwork(target)
            for ip in exit_addresses:
                if IPAddress(ip) in netblock:
                    self.debug(f"IP address {ip} found within netblock/subnet {target} in TOR exit node list.")
                    return True

        return False

    def retrieveExitNodes(self):
        exit_addresses = self.sf.cacheGet('torexitnodes', 24)

        if exit_addresses is not None:
            return self.parseExitNodes(exit_addresses)

        res = self.sf.fetchUrl(
            "https://check.torproject.org/exit-addresses",
            timeout=self.opts['_fetchtimeout'],
            useragent=self.opts['_useragent'],
        )

        if res['code'] != "200":
            self.error(f"Unexpected HTTP response code {res['code']} from check.torproject.org.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.error("Received no content from check.torproject.org.")
            self.errorState = True
            return None

        self.sf.cachePut("torexitnodes", res['content'])

        return self.parseExitNodes(res['content'])

    def parseExitNodes(self, exit_addresses):
        """Parse TOR exit node list data

        Args:
            exit_addresses (str): TOR exit node list data

        Returns:
            list: list of TOR exit IP addresses
        """
        ips = list()

        if not exit_addresses:
            return ips

        matches = re.findall(r"ExitAddress\s+([\d\.]+)\s+", exit_addresses)
        for ip in matches:
            if self.sf.validIP(ip):
                ips.append(ip)

        return ips

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if self.errorState:
            return

        self.results[eventData] = True

        if eventName == 'IP_ADDRESS':
            targetType = 'ip'
            evtType = 'MALICIOUS_IPADDR'
        elif eventName == 'AFFILIATE_IPADDR':
            if not self.opts.get('checkaffiliates', False):
                return
            targetType = 'ip'
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts.get('checknetblocks', False):
                return
            targetType = 'netblock'
            evtType = 'MALICIOUS_NETBLOCK'
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts.get('checksubnets', False):
                return
            targetType = 'netblock'
            evtType = 'MALICIOUS_SUBNET'
        else:
            return

        self.debug(f"Checking if {eventData} ({eventName}) is a TOR exit node")

        if self.queryExitNodes(eventData, targetType):
            url = "https://check.torproject.org/exit-addresses"
            text = f"TOR Exits List [{eventData}]\n<SFURL>{url}</SFURL>"
            evt = SpiderFootEvent(evtType, text, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_torexits class
