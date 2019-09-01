# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_cmseek
# Purpose:      SpiderFoot plug-in for using the 'CMSeeK' tool.
#               Tool: https://github.com/Tuhinshubhra/CMSeeK
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     16/12/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

from subprocess import Popen, PIPE
import io
import json
import os.path
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_tool_cmseek(SpiderFootPlugin):
    """Tool - CMSeeK:Footprint,Investigate:Content Analysis:tool:Identify what Content Management System (CMS) might be used."""


    # Default options
    opts = {
        'pythonpath': "python3",
        'cmseekpath': ""
    }

    # Option descriptions
    optdescs = {
        'pythonpath': "Path to Python 3 interpreter to use for CMSeeK. If just 'python3' then it must be in your PATH.",
        'cmseekpath': "Path to the where the cmseek.py file lives. Must be set."
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

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['INTERNET_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["WEBSERVER_TECHNOLOGY"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.errorState:
            return None

        # Don't look up stuff twice, check IP == IP here
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already scanned.")
            return None
        else:
            self.results[eventData] = True

        if not self.opts['cmseekpath']:
            self.sf.error("You enabled sfp_tool_cmseek but did not set a path to the tool!", False)
            self.errorState = True
            return None

        # Normalize path
        if self.opts['cmseekpath'].endswith('cmseek.py'):
            exe = self.opts['cmseekpath']
            resultpath = self.opts['cmseekpath'].split("cmseek.py")[0] + "/Result"
        elif self.opts['cmseekpath'].endswith('/'):
            exe = self.opts['cmseekpath'] + "cmseek.py"
            resultpath = self.opts['cmseekpath'] + "Result"
        else:
            exe = self.opts['cmseekpath'] + "/cmseek.py"
            resultpath = self.opts['cmseekpath'] + "/Result"

        # If tool is not found, abort
        if not os.path.isfile(exe):
            self.sf.error("File does not exist: " + exe, False)
            self.errorState = True
            return None

        # Sanitize domain name.
        if not self.sf.sanitiseInput(eventData):
            self.sf.error("Invalid input, refusing to run.", False)
            return None

        try:
            p = Popen([self.opts['pythonpath'], exe, "--follow-redirect", "-u", eventData], stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None)
            if p.returncode == 0:
                content = stdout
            else:
                self.sf.error("Unable to read CMSeeK content.", False)
                self.sf.debug("Error running CMSeeK: " + stderr + ", " + stdout)
                return None

            if "CMS Detection failed" in content:
                self.sf.debug("Couldn't detect the CMS for " + eventData)
                return None

            try:
                f = io.open(resultpath + "/" + eventData + "/cms.json", encoding='utf-8')
                j = json.loads(f.read())
                evt = SpiderFootEvent("WEBSERVER_TECHNOLOGY", j['cms_name'],
                                       self.__name__, event)
                self.notifyListeners(evt)
            except BaseException as e:
                self.sf.error("Couldn't parse the JSON output of CMSeeK: " + str(e), False)
                return None
        except BaseException as e:
            self.sf.error("Unable to run CMSeeK: " + str(e), False)
            return None

# End of sfp_tool_cmseek class
