# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_snallygaster
# Purpose:     SpiderFoot plug-in for using the snallygaster tool.
#              Tool: https://github.com/hannob/snallygaster
#
# Author:      <steve@binarypool.com>
#
# Created:     2022-04-02
# Copyright:   (c) Steve Micallef 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import sys
import json
import os.path
from subprocess import PIPE, Popen, TimeoutExpired

from spiderfoot import SpiderFootPlugin, SpiderFootEvent, SpiderFootHelpers


class sfp_tool_snallygaster(SpiderFootPlugin):

    meta = {
        "name": "Tool - snallygaster",
        "summary": "Finds file leaks and other security problems on HTTP servers.",
        "flags": ["tool"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Crawling and Scanning"],
        "toolDetails": {
            "name": "snallygaster",
            "description": "snallygaster is a tool that looks for files accessible on "
                           "web servers that shouldn't be public and can pose a security "
                           "risk. Typical examples include publicly accessible git "
                           "repositories, backup files potentially containing passwords "
                           " or database dumps. In addition, it contains a few checks "
                           " for other security vulnerabilities.",
            "website": "https://github.com/hannob/snallygaster",
            "repository": "https://github.com/hannob/snallygaster"
        }
    }

    opts = {
        'snallygaster_path': ''
    }

    optdescs = {
        "snallygaster_path": "Path to your snallygaster binary. Must be set."
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
        return ['INTERNET_NAME']

    def producedEvents(self):
        return [
            'VULNERABILITY_GENERAL',
            'VULNERABILITY_CVE_CRITICAL',
            'VULNERABILITY_CVE_HIGH',
            'VULNERABILITY_CVE_MEDIUM',
            'VULNERABILITY_CVE_LOW'
        ]

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already scanned.")
            return

        self.results[eventData] = True

        if not self.opts['snallygaster_path']:
            self.error("You enabled sfp_tool_snallygaster but did not set a path to the tool!")
            self.errorState = True
            return

        exe = self.opts["snallygaster_path"]
        if self.opts["snallygaster_path"].endswith("/"):
            exe = f"{exe}snallygaster"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if not SpiderFootHelpers.sanitiseInput(eventData):
            self.error("Invalid input, refusing to run.")
            return

        args = [
            exe,
            '--nowww',
            '-j',
            eventData
        ]
        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            out, stderr = p.communicate(input=None, timeout=600)
            stdout = out.decode(sys.stdin.encoding)
        except TimeoutExpired:
            p.kill()
            stdout, stderr = p.communicate()
            self.debug(f"Timed out waiting for snallygaster to finish on {eventData}")
            return
        except Exception as e:
            self.error(f"Unable to run snallygaster: {e}")
            return

        if p.returncode != 0:
            self.error(f"Unable to read onesixtyone output\nstderr: {stderr}\nstdout: {stdout}")
            return

        if not stdout:
            self.debug(f"snallygaster returned no output for {eventData}")
            return

        try:
            result_json = json.loads(stdout)
        except Exception as e:
            self.error(f"Could not parse snallygaster output as JSON: {e}\nstderr: {stderr}\nstdout: {stdout}")
            return

        if not result_json:
            self.debug(f"snallygaster returned no output for {eventData}")
            return

        for res in result_json:
            if "cause" not in res:
                continue

            text = f"Cause: {res['cause']}\nURL: {res['url']}"
            if res["misc"]:
                text += f"\nAdditional Info: {res['misc']}"
            evt = SpiderFootEvent(
                "VULNERABILITY_GENERAL",
                text,
                self.__name__,
                event,
            )
            self.notifyListeners(evt)

# End of sfp_tool_snallygaster class
