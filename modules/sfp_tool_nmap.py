# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_nmap
# Purpose:      SpiderFoot plug-in for using nmap to perform OS fingerprinting.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     03/05/2020
# Copyright:   (c) Steve Micallef 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import os.path
from subprocess import PIPE, Popen

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_nmap(SpiderFootPlugin):

    meta = {
        'name': "Tool - Nmap",
        'summary': "Identify what Operating System might be used.",
        'flags': ["tool", "slow", "invasive"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "Nmap",
            'description': "Nmap (\"Network Mapper\") is a free and open source utility for network discovery and security auditing.\n"
            "Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, "
            "what services (application name and version) those hosts are offering, "
            "what operating systems (and OS versions) they are running, "
            "what type of packet filters/firewalls are in use, and dozens of other characteristics.\n",
            'website': "https://nmap.org/",
            'repository': "https://svn.nmap.org/nmap"
        },
    }

    # Default options
    opts = {
        'nmappath': "",
        'netblockscan': True,
        'netblockscanmax': 24
    }

    # Option descriptions
    optdescs = {
        'nmappath': "Path to the where the nmap binary lives. Must be set.",
        'netblockscan': "Port scan all IPs within identified owned netblocks?",
        'netblockscanmax': "Maximum netblock/subnet size to scan IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.__dataSource__ = "Target Network"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'NETBLOCK_OWNER']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["OPERATING_SYSTEM", "IP_ADDRESS"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if srcModuleName == "sfp_tool_nmap":
            self.debug("Skipping event from myself.")
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        try:
            if eventName == "NETBLOCK_OWNER" and self.opts['netblockscan']:
                net = IPNetwork(eventData)
                if net.prefixlen < self.opts['netblockscanmax']:
                    self.debug("Skipping port scanning of " + eventData + ", too big.")
                    return

        except Exception as e:
            self.error("Strange netblock identified, unable to parse: " + eventData + " (" + str(e) + ")")
            return

        # Don't look up stuff twice, check IP == IP here
        if eventData in self.results:
            self.debug("Skipping " + eventData + " as already scanned.")
            return
        else:
            # Might be a subnet within a subnet or IP within a subnet
            for addr in self.results:
                if IPNetwork(eventData) in IPNetwork(addr):
                    self.debug("Skipping " + eventData + " as already within a scanned range.")
                    return

        self.results[eventData] = True

        if not self.opts['nmappath']:
            self.error("You enabled sfp_tool_nmap but did not set a path to the tool!")
            self.errorState = True
            return

        # Normalize path
        if self.opts['nmappath'].endswith('nmap'):
            exe = self.opts['nmappath']
        elif self.opts['nmappath'].endswith('/'):
            exe = self.opts['nmappath'] + "nmap"
        else:
            self.error("Could not recognize your nmap path configuration.")
            self.errorState = True

        # If tool is not found, abort
        if not os.path.isfile(exe):
            self.error("File does not exist: " + exe)
            self.errorState = True
            return

        # Sanitize domain name.
        if not self.sf.validIP(eventData) and not self.sf.validIpNetwork(eventData):
            self.error("Invalid input, refusing to run.")
            return

        try:
            p = Popen([exe, "-O", "--osscan-limit", eventData], stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None)
            if p.returncode == 0:
                content = stdout.decode('utf-8', errors='replace')
            else:
                self.error("Unable to read Nmap content.")
                self.debug(f"Error running Nmap: {stderr}, {stdout}")
                return

            if "No exact OS matches for host" in content or "OSScan results may be unreliable" in content:
                self.debug(f"Couldn't reliably detect the OS for {eventData}")
                return
        except Exception as e:
            self.error(f"Unable to run Nmap: {e}")
            return

        if not content:
            self.debug("No content from Nmap to parse.")
            return

        if eventName == "IP_ADDRESS":
            try:
                opsys = None
                for line in content.split('\n'):
                    if "OS details:" in line:
                        junk, opsys = line.split(": ")
                if opsys:
                    evt = SpiderFootEvent("OPERATING_SYSTEM", opsys, self.__name__, event)
                    self.notifyListeners(evt)
            except Exception as e:
                self.error("Couldn't parse the output of Nmap: " + str(e))
                return

        if eventName == "NETBLOCK_OWNER":
            try:
                currentIp = None
                for line in content.split('\n'):
                    opsys = None
                    if "scan report for" in line:
                        currentIp = line.split("(")[1].replace(")", "")
                    if "OS details:" in line:
                        junk, opsys = line.split(": ")

                    if opsys and currentIp:
                        ipevent = SpiderFootEvent("IP_ADDRESS", currentIp, self.__name__, event)
                        self.notifyListeners(ipevent)

                        evt = SpiderFootEvent("OPERATING_SYSTEM", opsys, self.__name__, ipevent)
                        self.notifyListeners(evt)
                        currentIp = None
            except Exception as e:
                self.error(f"Couldn't parse the output of Nmap: {e}")
                return

# End of sfp_tool_nmap class
