# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_testsslsh
# Purpose:     SpiderFoot plug-in for using the testssl.sh tool.
#              Tool: https://github.com/drwetter/testssl.sh
#
# Author:      <steve@binarypool.com>
#
# Created:     2022-04-02
# Copyright:   (c) Steve Micallef 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import os
import sys
import json
import tempfile
from netaddr import IPNetwork
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootPlugin, SpiderFootEvent, SpiderFootHelpers


class sfp_tool_testsslsh(SpiderFootPlugin):

    meta = {
        'name': "Tool - testssl.sh",
        'summary': "Identify various TLS/SSL weaknesses, including Heartbleed, CRIME and ROBOT.",
        'flags': ["tool"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "testssl.sh",
            'description': "testssl.sh is a free command line tool which checks "
                           "a server's service on any port for the support of "
                           "TLS/SSL ciphers, protocols as well as some "
                           "cryptographic flaws.",
            'website': "https://testssl.sh",
            'repository': "https://github.com/drwetter/testssl.sh"
        },
    }

    opts = {
        'testsslsh_path': '',
        'netblockscan': True,
        'netblockscanmax': 24,
        'mincve': 'LOW'
    }

    optdescs = {
        'testsslsh_path': "Path to your testssl.sh executable. Must be set.",
        'netblockscan': "Test all IPs within identified owned netblocks?",
        'netblockscanmax': "Maximum netblock/subnet size to test IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'mincve': "Only report CVEs equal to or higher than this level, must be either LOW, MEDIUM, HIGH or CRITICAL."
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
        return ['INTERNET_NAME', 'IP_ADDRESS', 'NETBLOCK_OWNER']

    def producedEvents(self):
        return [
            'VULNERABILITY_CVE_CRITICAL',
            'VULNERABILITY_CVE_HIGH',
            'VULNERABILITY_CVE_MEDIUM',
            'VULNERABILITY_CVE_LOW',
            'VULNERABILITY_GENERAL',
            'IP_ADDRESS'
        ]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if srcModuleName == "sfp_tool_testsslsh":
            self.debug("Skipping event from myself.")
            return

        if not self.opts['testsslsh_path']:
            self.error("You enabled sfp_tool_testsslsh but did not set a path to the tool!")
            self.errorState = True
            return

        if self.opts['mincve'].upper().strip() not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            self.error("Invalid CVE threshold configuration. Must be CRITICAL, HIGH, MEDIUM or LOW.")
            self.errorState = True
            return

        exe = self.opts['testsslsh_path']
        if self.opts['testsslsh_path'].endswith('/'):
            exe = f"{exe}testssl.sh"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if not SpiderFootHelpers.sanitiseInput(eventData, extra=['/']):
            self.debug("Invalid input, skipping.")
            return

        targets = list()
        try:
            if eventName == "NETBLOCK_OWNER" and self.opts['netblockscan']:
                net = IPNetwork(eventData)
                if net.prefixlen < self.opts['netblockscanmax']:
                    self.debug("Skipping scanning of " + eventData + ", too big.")
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

        if eventName != "INTERNET_NAME":
            # Might be a subnet within a subnet or IP within a subnet
            for addr in self.results:
                try:
                    if IPNetwork(eventData) in IPNetwork(addr):
                        self.debug(f"Skipping {eventData} as already within a scanned range.")
                        return
                except BaseException:
                    # self.results will also contain hostnames
                    continue

        # If we weren't passed a netblock, this will be empty
        if not targets:
            targets.append(eventData)

        for target in targets:
            self.results[target] = True

            # Create a temporary output file
            _, fname = tempfile.mkstemp("testssl.json")

            args = [
                exe,
                "-U",
                "--connect-timeout",
                "5",
                "--openssl-timeout",
                "5",
                "--severity",
                self.opts['mincve'].upper().strip(),
                "--jsonfile",
                fname,
                target
            ]
            try:
                p = Popen(args, stdout=PIPE, stderr=PIPE)
                out, stderr = p.communicate(input=None, timeout=300)
                stdout = out.decode(sys.stdin.encoding)
            except TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                self.debug(f"Timed out waiting for testssl.sh to finish on {target}")
                continue
            except Exception as e:
                self.error(f"Unable to run testssl.sh: {e}")
                os.unlink(fname)
                continue

            if p.returncode != 0:
                if "Unable to open a socket" in stdout:
                    self.debug(f"Unable to read testssl.sh output for {target}: Unable to connect")
                else:
                    self.error(f"Unable to read testssl.sh output for {target}: Internal error")
                os.unlink(fname)
                continue

            if not stdout:
                self.debug(f"testssl.sh returned no output for {target}")
                os.unlink(fname)
                continue

            try:
                with open(fname, "r") as f:
                    result_json = json.loads(f.read())
                os.unlink(fname)
            except Exception as e:
                self.error(f"Could not parse testssl.sh output as JSON: {e}\nstderr: {stderr}\nstdout: {stdout}")
                continue

            if not result_json:
                self.debug(f"testssl.sh returned no output for {target}")
                continue

            pevent = event
            # For netblocks, we need to create the IP address event so that
            # the event is more meaningful but check if we have applicable
            # vulnerabilities to report.
            if eventName == 'NETBLOCK_OWNER':
                generate = False
                for result in result_json:
                    if result['finding'] == "not vulnerable":
                        continue

                    if result['severity'] not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                        continue

                    generate = True

                if generate:
                    pevent = SpiderFootEvent("IP_ADDRESS", target, self.__name__, event)
                    self.notifyListeners(pevent)

            cves = list()
            for result in result_json:
                if result['finding'] == "not vulnerable":
                    continue

                if result['severity'] not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                    continue

                if 'cve' in result:
                    for cve in result['cve'].split(" "):
                        if cve in cves:
                            continue
                        cves.append(cve)
                        etype, cvetext = self.sf.cveInfo(cve)
                        evt = SpiderFootEvent(etype, cvetext, self.__name__, pevent)
                        self.notifyListeners(evt)
                else:
                    if result['id'] in cves:
                        continue
                    cves.append(result['id'])
                    evt = SpiderFootEvent("VULNERABILITY_GENERAL", f"{result['id']} ({result['finding']})", self.__name__, pevent)
                    self.notifyListeners(evt)

# End of sfp_tool_testsslsh class
