# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_nuclei
# Purpose:      SpiderFoot plug-in for using the 'Nuclei' tool.
#               Tool: https://github.com/EnableSecurity/nuclei
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     2022-04-02
# Copyright:   (c) Steve Micallef 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import os
import re
import sys
import json
from netaddr import IPNetwork
from subprocess import Popen, PIPE, TimeoutExpired

from spiderfoot import SpiderFootPlugin, SpiderFootEvent, SpiderFootHelpers


class sfp_tool_nuclei(SpiderFootPlugin):

    meta = {
        "name": "Tool - Nuclei",
        "summary": "Fast and customisable vulnerability scanner.",
        "flags": [
            "tool",
            "slow",
            "invasive"
        ],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "name": "Nuclei",
            "description": "Fast and customisable vulnerability scanner based on simple YAML based DSL.",
            "website": "https://nuclei.projectdiscovery.io/",
            "repository": "https://github.com/projectdiscovery/nuclei"
        }
    }

    # Default options
    opts = {
        "nuclei_path": "",
        "template_path": "",
        'netblockscan': True,
        'netblockscanmax': 24
    }

    # Option descriptions
    optdescs = {
        'nuclei_path': "The path to your nuclei binary. Must be set.",
        'template_path': "The path to your nuclei templates. Must be set.",
        'netblockscan': "Check all IPs within identified owned netblocks?",
        'netblockscanmax': "Maximum netblock/subnet size to scan IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    # Target
    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ["INTERNET_NAME", "IP_ADDRESS", "NETBLOCK_OWNER"]

    def producedEvents(self):
        return [
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "IP_ADDRESS",
            "VULNERABILITY_GENERAL",
            "WEBSERVER_TECHNOLOGY"
        ]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if srcModuleName == "sfp_tool_nuclei":
            return

        if not self.opts['nuclei_path'] or not self.opts['template_path']:
            self.error("You enabled sfp_tool_nuclei but did not set a path to the tool and/or templates!")
            self.errorState = True
            return

        exe = self.opts['nuclei_path']
        if self.opts['nuclei_path'].endswith('/'):
            exe = f"{exe}nuclei"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if not SpiderFootHelpers.sanitiseInput(eventData, extra=['/']):
            self.debug("Invalid input, skipping.")
            return

        # Don't look up stuff twice
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

        self.results[eventData] = True

        timeout = 240
        try:
            target = eventData
            if eventName == "NETBLOCK_OWNER" and self.opts['netblockscan']:
                target = ""
                net = IPNetwork(eventData)
                if net.prefixlen < self.opts['netblockscanmax']:
                    self.debug(f"Skipping scanning of {eventData}, too big.")
                    return

                # Nuclei doesn't support targeting subnets directly,
                # so for now work around that by listing each IP.
                for addr in IPNetwork(eventData).iter_hosts():
                    target += str(addr) + "\n"
                    timeout += 240
        except BaseException as e:
            self.error(f"Strange netblock identified, unable to parse: {eventData} ({e})")
            return

        try:
            args = [
                exe,
                "-silent",
                "-json",
                "-concurrency",
                "100",
                "-retries",
                "1",
                "-t",
                self.opts["template_path"],
                "-no-interactsh",
                "-etags",
                "dos",
                "fuzz",
                "misc",
            ]
            p = Popen(args, stdin=PIPE, stdout=PIPE, stderr=PIPE)
            try:
                stdout, stderr = p.communicate(input=target.encode(sys.stdin.encoding), timeout=timeout)
                if p.returncode == 0:
                    content = stdout.decode(sys.stdout.encoding)
                else:
                    self.error("Unable to read Nuclei content.")
                    self.debug(f"Error running Nuclei: {stderr}, {stdout}")
                    return
            except TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                self.debug("Timed out waiting for Nuclei to finish")
                return
        except BaseException as e:
            self.error(f"Unable to run Nuclei: {e}")
            return

        if not content:
            return

        try:
            for line in content.split("\n"):
                if not line:
                    continue

                data = json.loads(line)
                srcevent = event
                host = data['matched-at'].split(":")[0]
                if host != eventData:
                    if self.sf.validIP(host):
                        srctype = "IP_ADDRESS"
                    else:
                        srctype = "INTERNET_NAME"
                    srcevent = SpiderFootEvent(srctype, host, self.__name__, event)
                    self.notifyListeners(srcevent)

                matches = re.findall(r"CVE-\d{4}-\d{4,7}", line)
                if matches:
                    for cve in matches:
                        etype, cvetext = self.sf.cveInfo(cve)
                        e = SpiderFootEvent(
                            etype, cvetext, self.__name__, srcevent
                        )
                        self.notifyListeners(e)
                else:
                    if "matcher-name" in data:
                        etype = "VULNERABILITY_GENERAL"
                        if data['info']['severity'] == "info":
                            etype = "WEBSERVER_TECHNOLOGY"

                        datatext = f"Template: {data['info']['name']}({data['template-id']})\n"
                        datatext += f"Matcher: {data['matcher-name']}\n"
                        datatext += f"Matched at: {data['matched-at']}\n"
                        if data['info'].get('reference'):
                            datatext += f"Reference: <SFURL>{data['info']['reference'][0]}</SFURL>"

                        evt = SpiderFootEvent(
                            etype,
                            datatext,
                            self.__name__,
                            srcevent,
                        )
                        self.notifyListeners(evt)
        except (KeyError, ValueError) as e:
            self.error(f"Couldn't parse the JSON output of Nuclei: {e}")
            self.error(f"Nuclei content: {content}")
            return


# End of sfp_tool_nuclei class
