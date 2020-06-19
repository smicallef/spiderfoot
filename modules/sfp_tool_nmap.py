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

from subprocess import Popen, PIPE
import io
import json
import os.path
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_tool_nmap(SpiderFootPlugin):
    """Tool - Nmap:Footprint,Investigate:Crawling and Scanning:tool,slow,invasive:Identify what Operating System might be used."""

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
        return ["OPERATING_SYSTEM"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if srcModuleName == "sfp_tool_nmap":
            self.sf.debug("Skipping event from myself.")
            return None

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if self.errorState:
            return None

        try:
            if eventName == "NETBLOCK_OWNER" and self.opts['netblockscan']:
                net = IPNetwork(eventData)
                if net.prefixlen < self.opts['netblockscanmax']:
                    self.sf.debug("Skipping port scanning of " + eventData + ", too big.")
                    return None

        except BaseException as e:
            self.sf.error("Strange netblock identified, unable to parse: " +
                          eventData + " (" + str(e) + ")", False)
            return None

        # Don't look up stuff twice, check IP == IP here
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already scanned.")
            return None
        else:
            # Might be a subnet within a subnet or IP within a subnet
            for addr in self.results:
                if IPNetwork(eventData) in IPNetwork(addr):
                    self.sf.debug("Skipping " + eventData + " as already within a scanned range.")
                    return None

        self.results[eventData] = True

        if not self.opts['nmappath']:
            self.sf.error("You enabled sfp_tool_nmap but did not set a path to the tool!", False)
            self.errorState = True
            return None

        # Normalize path
        if self.opts['nmappath'].endswith('nmap'):
            exe = self.opts['nmappath']
        elif self.opts['nmappath'].endswith('/'):
            exe = self.opts['nmappath'] + "nmap"
        else:
            self.sf.error("Could not recognize your nmap path configuration.", False)
            self.errorState = True

        # If tool is not found, abort
        if not os.path.isfile(exe):
            self.sf.error("File does not exist: " + exe, False)
            self.errorState = True
            return None

        # Sanitize domain name.
        if not self.sf.validIP(eventData) and not self.sf.validIpNetwork(eventData):
            self.sf.error("Invalid input, refusing to run.", False)
            return None

        try:
            p = Popen([exe, "-O", "--osscan-limit", eventData], stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None)
            if p.returncode == 0:
                content = stdout.decode('utf-8', errors='replace')
            else:
                self.sf.error("Unable to read Nmap content.", False)
                self.sf.debug("Error running Nmap: " + stderr + ", " + stdout)
                return None

            if "No exact OS matches for host" in content or "OSScan results may be unreliable" in content:
                self.sf.debug("Couldn't reliably detect the OS for " + eventData)
                return None
        except BaseException as e:
            self.sf.error("Unable to run Nmap: " + str(e), False)
            return None

        if not content:
            self.sf.debug("No content from Nmap to parse.")
            return None

        if eventName == "IP_ADDRESS":
            try:
                opsys = None
                for line in content.split('\n'):
                    if "OS details:" in line:
                        junk, opsys = line.split(": ")
                if opsys:
                    evt = SpiderFootEvent("OPERATING_SYSTEM", opsys,
                                           self.__name__, event)
                    self.notifyListeners(evt)
            except BaseException as e:
                self.sf.error("Couldn't parse the output of Nmap: " + str(e), False)
                return None

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
                        ipevent = SpiderFootEvent("IP_ADDRESS", currentIp,
                                               self.__name__, event)
                        self.notifyListeners(ipevent)

                        evt = SpiderFootEvent("OPERATING_SYSTEM", opsys,
                                               self.__name__, ipevent)
                        self.notifyListeners(evt)
                        currentIp = None
            except BaseException as e:
                self.sf.error("Couldn't parse the output of Nmap: " + str(e), False)
                return None

# End of sfp_tool_nmap class
