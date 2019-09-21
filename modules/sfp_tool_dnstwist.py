# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_dnstwist
# Purpose:      SpiderFoot plug-in for using the 'dnstwist' tool.
#               Tool: https://github.com/elceef/dnstwist
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/11/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

from subprocess import Popen, PIPE
import json
import os.path
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_tool_dnstwist(SpiderFootPlugin):
    """Tool - DNSTwist:Footprint,Investigate:DNS:tool:Identify bit-squatting, typo and other similar domains to the target using a local DNSTwist installation."""


    # Default options
    opts = {
        'pythonpath': "python",
        'dnstwistpath': ""
    }

    # Option descriptions
    optdescs = {
        'pythonpath': "Path to Python interpreter to use for DNSTwist. If just 'python' then it must be in your PATH.",
        'dnstwistpath': "Path to the where the dnstwist.py file lives. Must be set."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.errorState = False
        self.__dataSource__ = "DNS"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['DOMAIN_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SIMILARDOMAIN"]

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

        if not self.opts['dnstwistpath']:
            self.sf.error("You enabled sfp_tool_dnstwist but did not set a path to the tool!", False)
            self.errorState = True
            return None

        # Normalize path
        if self.opts['dnstwistpath'].endswith('dnstwist.py'):
            exe = self.opts['dnstwistpath']
        elif self.opts['dnstwistpath'].endswith('/'):
            exe = self.opts['dnstwistpath'] + "dnstwist.py"
        else:
            exe = self.opts['dnstwistpath'] + "/dnstwist.py"

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
            p = Popen([self.opts['pythonpath'], exe, "-f", "json", "-r", eventData], stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None)
            if p.returncode == 0:
                content = stdout
            else:
                self.sf.error("Unable to read DNSTwist content.", False)
                self.sf.debug("Error running DNSTwist: " + stderr + ", " + stdout)
                return None

            # For each line in output, generate a SIMILARDOMAIN event
            try:
                j = json.loads(content)
                for r in j:
                    evt = SpiderFootEvent("SIMILARDOMAIN", r['domain-name'],
                                           self.__name__, event)
                    self.notifyListeners(evt)
            except BaseException as e:
                self.sf.error("Couldn't parse the JSON output of DNSTwist: " + str(e), False)
                return None
        except BaseException as e:
            self.sf.error("Unable to run DNSTwist: " + str(e), False)
            return None

# End of sfp_tool_dnstwist class
