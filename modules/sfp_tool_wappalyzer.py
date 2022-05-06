# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_wappalyzer
# Purpose:      SpiderFoot plug-in for using the 'Wappalyzer' tool.
#               Tool: https://github.com/EnableSecurity/wappalyzer
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     2022-04-02
# Copyright:   (c) Steve Micallef 2022
# Licence:     MIT
# -------------------------------------------------------------------------------

import os
import sys
import json
from subprocess import Popen, PIPE, TimeoutExpired

from spiderfoot import SpiderFootPlugin, SpiderFootEvent, SpiderFootHelpers


class sfp_tool_wappalyzer(SpiderFootPlugin):

    meta = {
        "name": "Tool - Wappalyzer",
        "summary": "Wappalyzer indentifies technologies on websites.",
        "flags": ["tool"],
        "useCases": ["Footprint", "Investigate"],
        "categories": ["Content Analysis"],
        "toolDetails": {
            "name": "Wappalyzer",
            "description": "Wappalyzer identifies technologies on websites, including content management systems, ecommerce platforms, JavaScript frameworks, analytics tools and much more.",
            "website": "https://www.wappalyzer.com/",
            "repository": "https://github.com/AliasIO/Wappalyzer"
        }
    }

    # Default options
    opts = {
        "node_path": "/usr/bin/node",
        "wappalyzer_path": ""
    }

    # Option descriptions
    optdescs = {
        "node_path": "Path to your NodeJS binary. Must be set.",
        "wappalyzer_path": "Path to your wappalyzer cli.js file. Must be set.",
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
        return ["INTERNET_NAME"]

    def producedEvents(self):
        return ["OPERATING_SYSTEM", "SOFTWARE_USED", "WEBSERVER_TECHNOLOGY"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if not self.opts['wappalyzer_path']:
            self.error("You enabled sfp_tool_wappalyzer but did not set a path to the tool!")
            self.errorState = True
            return

        exe = self.opts['wappalyzer_path']
        if self.opts['wappalyzer_path'].endswith('/'):
            exe = f"{exe}cli.js"

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        if not SpiderFootHelpers.sanitiseInput(eventData):
            self.debug("Invalid input, skipping.")
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already scanned.")
            return
        self.results[eventData] = True

        try:
            args = [self.opts["node_path"], exe, f"https://{eventData}"]
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            try:
                stdout, stderr = p.communicate(input=None, timeout=60)
                if p.returncode == 0:
                    content = stdout.decode(sys.stdin.encoding)
                else:
                    self.error("Unable to read Wappalyzer content.")
                    self.error(f"Error running Wappalyzer: {stderr}, {stdout}")
                    return
            except TimeoutExpired:
                p.kill()
                stdout, stderr = p.communicate()
                self.debug("Timed out waiting for Wappalyzer to finish")
                return
        except BaseException as e:
            self.error(f"Unable to run Wappalyzer: {e}")
            return

        try:
            data = json.loads(content)
            for item in data["technologies"]:
                for cat in item["categories"]:
                    if cat["name"] == "Operating systems":
                        evt = SpiderFootEvent(
                            "OPERATING_SYSTEM",
                            item["name"],
                            self.__name__,
                            event,
                        )
                    elif cat["name"] == "Web servers":
                        evt = SpiderFootEvent(
                            "WEBSERVER_TECHNOLOGY",
                            item["name"],
                            self.__name__,
                            event,
                        )
                    else:
                        evt = SpiderFootEvent(
                            "SOFTWARE_USED",
                            item["name"],
                            self.__name__,
                            event,
                        )
                    self.notifyListeners(evt)
        except (KeyError, ValueError) as e:
            self.error(f"Couldn't parse the JSON output of Wappalyzer: {e}")
            self.error(f"Wappalyzer content: {content}")
            return


# End of sfp_tool_wappalyzer class
