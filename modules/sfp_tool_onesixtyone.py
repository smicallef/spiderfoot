# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_onesixtyone
# Purpose:     SpiderFoot plug-in for using the onesixtyone tool.
#              Tool: https://github.com/trailofbits/onesixtyone
#
# Author:      <steve@binarypool.com>
#
# Created:     2022-04-02
# Copyright:   (c) Steve Micallef 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import sys
import os.path
import tempfile
from netaddr import IPNetwork
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootPlugin, SpiderFootEvent, SpiderFootHelpers


class sfp_tool_onesixtyone(SpiderFootPlugin):

    meta = {
        "name": "Tool - onesixtyone",
        "summary": "Fast scanner to find publicly exposed SNMP services.",
        "flags": ["tool"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "name": "onesixtyone",
            "description": "onesixtyone is a fast scanner for finding publicly exposed SNMP services.",
            "website": "https://github.com/trailofbits/onesixtyone",
            "repository": "https://github.com/trailofbits/onesixtyone"
        }
    }

    opts = {
        'onesixtyone_path': '',
        'communities': '1234,2read,4changes,CISCO,IBM,OrigEquipMfr,SNMP,SUN,access,admin,agent,all,cisco,community,default,enable,field,guest,hello,ibm,manager,mngt,monitor,netman,network,none,openview,pass,password,private,proxy,public,read,read-only,read-write,root,router,secret,security,snmp,snmpd,solaris,sun,switch,system,tech,test,world,write',
        'netblockscan': True,
        'netblockscanmax': 24
    }

    optdescs = {
        'onesixtyone_path': "The path to your onesixtyone binary. Must be set.",
        'communities': "Comma-separated list of SNMP communities to try.",
        'netblockscan': "Scan all IPs within identified owned netblocks?",
        'netblockscanmax': "Maximum netblock/subnet size to scan IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    results = None
    errorState = False
    communitiesFile = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.errorState = False
        self.__dataSource__ = "Target Website"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # Write communities to file for use later on
        try:
            _, self.communitiesFile = tempfile.mkstemp("communities")
            with open(self.communitiesFile, "w") as f:
                for community in self.opts['communities'].split(","):
                    f.write(community.strip() + "\n")
        except BaseException as e:
            self.error(f"Unable to write communities file ({self.communitiesFile}): {e}")
            self.errorState = True

    def watchedEvents(self):
        return ['IP_ADDRESS', 'NETBLOCK_OWNER']

    def producedEvents(self):
        return [
            'UDP_PORT_OPEN_INFO',
            'UDP_PORT_OPEN',
            'IP_ADDRESS'
        ]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if srcModuleName == "sfp_tool_onesixtyone":
            self.debug("Skipping event from myself.")
            return

        if not self.opts['onesixtyone_path']:
            self.error("You enabled sfp_tool_onesixtyone but did not set a path to the tool!")
            self.errorState = True
            return

        exe = self.opts['onesixtyone_path']
        if self.opts['onesixtyone_path'].endswith('/'):
            exe = f"{exe}onesixtyone"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if not SpiderFootHelpers.sanitiseInput(eventData, extra=['/']):
            self.debug("Invalid input, skipping.")
            return

        targets = []
        try:
            if eventName == "NETBLOCK_OWNER" and self.opts['netblockscan']:
                net = IPNetwork(eventData)
                if net.prefixlen < self.opts['netblockscanmax']:
                    self.debug(f"Skipping scanning of {eventData}, too big.")
                    return
                for addr in net.iter_hosts():
                    targets.append(str(addr))
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

        # If we weren't passed a netblock, this will be empty
        if not targets:
            targets.append(eventData)

        for target in targets:
            args = [
                exe,
                "-c",
                self.communitiesFile,
                target
            ]
            try:
                p = Popen(args, stdout=PIPE, stderr=PIPE)
                out, stderr = p.communicate(input=None, timeout=60)
                stdout = out.decode(sys.stdin.encoding)
            except TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                self.debug(f"Timed out waiting for onesixtyone to finish on {target}")
                continue
            except Exception as e:
                self.error(f"Unable to run onesixtyone: {e}")
                continue

            if p.returncode != 0:
                self.error(f"Unable to read onesixtyone output\nstderr: {stderr}\nstdout: {stdout}")
                continue

            if not stdout:
                self.debug(f"onesixtyone returned no output for {target}")
                continue

            for result in stdout.split("\n"):
                srcevent = event

                if target not in result:
                    continue

                if target != eventData:
                    srcevent = SpiderFootEvent("IP_ADDRESS", target, self.__name__, event)
                    self.notifyListeners(srcevent)

                e = SpiderFootEvent('UDP_PORT_OPEN', f"{target}:161", self.__name__, srcevent)
                self.notifyListeners(e)

                e = SpiderFootEvent("UDP_PORT_OPEN_INFO", result, self.__name__, e)
                self.notifyListeners(e)

# End of sfp_tool_onesixtyone class
