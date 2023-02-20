# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_nbtscan
# Purpose:     SpiderFoot plug-in for using the nbtscan tool.
#              Tool: http://www.unixwiz.net/tools/nbtscan.html
#
# Author:      <steve@binarypool.com>
#
# Created:     2022-04-02
# Copyright:   (c) Steve Micallef 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import sys
import os.path
from netaddr import IPNetwork
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootEvent, SpiderFootPlugin, SpiderFootHelpers


class sfp_tool_nbtscan(SpiderFootPlugin):

    meta = {
        "name": "Tool - nbtscan",
        "summary": "Scans for open NETBIOS nameservers on your target's network.",
        "flags": ["tool", "slow"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
                "name": "nbtscan",
                "description": "nbtscan is a tool that scans for open NETBIOS nameservers "
                               "on a local or remote TCP/IP network, and this is a first "
                               "step in finding of open shares. It is based on the functionality "
                               "of the standard Windows tool nbtstat, but it operates on a range "
                               "of addresses instead of just one.",
                "website": "http://www.unixwiz.net/tools/nbtscan.html",
                "repository": "http://www.unixwiz.net/tools/nbtscan.html"
        }
    }

    opts = {
        'nbtscan_path': '',
        'netblockscan': True,
        'netblockscanmax': 24
    }

    optdescs = {
        'nbtscan_path': "The path to your nbtscan binary",
        'netblockscan': "Scan all IPs within identified owned netblocks?",
        'netblockscanmax': "Maximum netblock/subnet size to scan IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.errorState = False
        self.__dataSource__ = "Target Website"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['IP_ADDRESS', 'NETBLOCK_OWNER']

    def producedEvents(self):
        return ['UDP_PORT_OPEN', 'UDP_PORT_OPEN_INFO', 'IP_ADDRESS']

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        timeout = 10

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if srcModuleName == "sfp_tool_nbtscan":
            self.debug("Skipping event from myself.")
            return

        if not self.opts['nbtscan_path']:
            self.error("You enabled sfp_tool_nbtscan but did not set a path to the tool!")
            self.errorState = True
            return

        exe = self.opts['nbtscan_path']
        if self.opts['nbtscan_path'].endswith('/'):
            exe = f"{exe}nbtscan"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if not SpiderFootHelpers.sanitiseInput(eventData, extra=['/']):
            self.debug("Invalid input, skipping.")
            return

        try:
            if eventName == "NETBLOCK_OWNER" and self.opts['netblockscan']:
                net = IPNetwork(eventData)
                if net.prefixlen < self.opts['netblockscanmax']:
                    self.debug(f"Skipping scanning of {eventData}, too big.")
                    return
                timeout = timeout * net.size
        except BaseException as e:
            self.error(f"Strange netblock identified, unable to parse: {eventData} ({e})")
            return

        # Don't look up stuff twice, check IP == IP here
        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already scanned.")
            return

        # Might be a subnet within a subnet or IP within a subnet
        for addr in self.results:
            if IPNetwork(eventData) in IPNetwork(addr):
                self.debug(f"Skipping {eventData} as already within a scanned range.")
                return

        self.results[eventData] = True

        args = [
            exe,
            "-v",
            eventData
        ]

        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            out, _ = p.communicate(input=None, timeout=timeout)
            stdout = out.decode(sys.stdin.encoding)
        except TimeoutExpired:
            p.kill()
            stdout, stderr = p.communicate()
            self.debug(f"Timed out waiting for nbtscan to finish on {eventData}")
            return
        except Exception as e:
            self.error(f"Unable to run nbtscan: {e}")
            return

        if not stdout:
            self.debug(f"nbtscan returned no output for {eventData}")
            return

        inside = False
        info = ""
        for row in stdout.split("\n"):
            if len(row) == 0:
                continue

            if "NetBIOS Name Table" in row:
                inside = True

            if "Adapter address" in row:
                info += f"{row}\n"
                inside = False

            if inside:
                info += f"{row}\n"

            if not inside and len(info) > 0:
                srcEvent = event
                addr = eventData
                if eventName == "NETBLOCK_OWNER":
                    # Extract the IP from the raw nbtscan output
                    addr = info.split("\n")[0].split("for Host ")[1].replace(":", "")
                    srcEvent = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                    self.notifyListeners(srcEvent)

                evt = SpiderFootEvent('UDP_PORT_OPEN', f"{addr}:137", self.__name__, srcEvent)
                self.notifyListeners(evt)

                evt = SpiderFootEvent('UDP_PORT_OPEN_INFO', info, self.__name__, evt)
                self.notifyListeners(evt)
                info = ""

# End of sfp_tool_nbtscan class
