# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_webtech
# Purpose:     SpiderFoot plug-in for using the 'WebTech' tool.
#              Tool: https://github.com/ShielderSec/webtech
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-10-04
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

from subprocess import Popen, PIPE
import io
import json
import os.path
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_tool_webtech(SpiderFootPlugin):
    """Tool - WebTech:Footprint,Investigate:Content Analysis:tool:Identify what software is in use on the specified website."""

    # Default options
    opts = {
        'python_path': 'python',
        'webtech_path': ''
    }

    # Option descriptions
    optdescs = {
        'python_path': "Path to Python interpreter to use for WebTech. If just 'python' then it must be in your $PATH.",
        'webtech_path': "Path to the webtech executable file. Must be set."
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
        return ['RAW_RIR_DATA', 'WEBSERVER_BANNER', 'WEBSERVER_TECHNOLOGY', 'SOFTWARE_USED']

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.errorState:
            return None

        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already scanned.")
            return None

        self.results[eventData] = True

        if not self.opts['webtech_path']:
            self.sf.error("You enabled sfp_tool_webtech but did not set a path to the tool!", False)
            self.errorState = True
            return None

        exe = self.opts['webtech_path']
        if self.opts['webtech_path'].endswith('/'):
            exe = exe + 'webtech'

        # If tool is not found, abort
        if not os.path.isfile(exe):
            self.sf.error("File does not exist: " + exe, False)
            self.errorState = True
            return None

        # Sanitize domain name.
        if not self.sf.sanitiseInput(eventData):
            self.sf.error("Invalid input, refusing to run.", False)
            return None

        # Run WebTech
        url = 'https://' + eventData
        args = [
            self.opts['python_path'],
            exe,
            "--json",
            "--user-agent=Mozilla/5.0",
            "-u", url
        ]
        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None)
        except BaseException as e:
            self.sf.error("Unable to run WebTech: " + str(e), False)
            return None

        if p.returncode != 0:
            self.sf.error("Unable to read WebTech output.", False)
            self.sf.debug("Error running WebTech: " + stderr + ", " + stdout)
            return None

        if not stdout:
            self.sf.debug("WebTech returned no output for " + eventData)
            return None

        try:
            result_json = json.loads(stdout)
        except BaseException as e:
            self.sf.error("Couldn't parse the JSON output of WebTech: " + str(e), False)
            return None

        evt = SpiderFootEvent('RAW_RIR_DATA', str(result_json), self.__name__, event)
        self.notifyListeners(evt)

        matches = result_json.get(url)

        if not matches:
            return None

        headers = matches.get('HTTPServer')
        if headers:
            server = headers.get('Server')
            if server:
                evt = SpiderFootEvent('WEBSERVER_BANNER', server, self.__name__, event)
                self.notifyListeners(evt)

        tech = matches.get('tech')
        for t in tech:
            software = t.get('name')
            #version = t.get('version')
            if software:
                evt = SpiderFootEvent('SOFTWARE_USED', software, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_tool_webtech class
