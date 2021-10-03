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

import json
from pathlib import Path
from shutil import which
from subprocess import PIPE, Popen

from spiderfoot import SpiderFootEvent, SpiderFootPlugin, SpiderFootHelpers


class sfp_tool_dnstwist(SpiderFootPlugin):

    meta = {
        'name': "Tool - DNSTwist",
        'summary': "Identify bit-squatting, typo and other similar domains to the target using a local DNSTwist installation.",
        'flags': ["tool"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["DNS"],
        'toolDetails': {
            'name': "DNSTwist",
            'description': "See what sort of trouble users can get in trying to type your domain name. "
            "Find lookalike domains that adversaries can use to attack you. "
            "Can detect typosquatters, phishing attacks, fraud, and brand impersonation. "
            "Useful as an additional source of targeted threat intelligence.",
            'website': 'https://github.com/elceef/dnstwist',
            'repository': 'https://github.com/elceef/dnstwist'
        },
    }

    # Default options
    opts = {
        'pythonpath': "python",
        'dnstwistpath': ""
    }

    # Option descriptions
    optdescs = {
        'pythonpath': "Path to Python interpreter to use for DNSTwist. If just 'python' then it must be in your PATH.",
        'dnstwistpath': "Path to the where the dnstwist.py file lives. Optional."
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.__dataSource__ = "DNS"

        for opt in list(userOpts.keys()):
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

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if eventData in self.results:
            self.debug("Skipping " + eventData + " as already scanned.")
            return

        self.results[eventData] = True

        dnstwistLocation = which('dnstwist')
        if dnstwistLocation and Path(dnstwistLocation).is_file():
            cmd = ['dnstwist']
        else:
            if not self.opts['dnstwistpath']:
                self.error("You enabled sfp_tool_dnstwist but did not set a path to the tool!")
                self.errorState = True
                return

            # Normalize path
            if self.opts['dnstwistpath'].endswith('dnstwist.py'):
                exe = self.opts['dnstwistpath']
            elif self.opts['dnstwistpath'].endswith('/'):
                exe = self.opts['dnstwistpath'] + "dnstwist.py"
            else:
                exe = self.opts['dnstwistpath'] + "/dnstwist.py"

            # If tool is not found, abort
            if not Path(exe).is_file():
                self.error("File does not exist: " + exe)
                self.errorState = True
                return

            cmd = [self.opts['pythonpath'], exe]

        # Sanitize domain name.
        if not SpiderFootHelpers.sanitiseInput(eventData):
            self.error("Invalid input, refusing to run.")
            return

        try:
            p = Popen(cmd + ["-f", "json", "-r", eventData], stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None)
            if p.returncode == 0:
                content = stdout
            else:
                self.error("Unable to read DNSTwist content.")
                self.debug("Error running DNSTwist: " + stderr + ", " + stdout)
                return

            # For each line in output, generate a SIMILARDOMAIN event
            try:
                j = json.loads(content)
                for r in j:
                    if self.getTarget().matches(r['domain-name']):
                        continue

                    evt = SpiderFootEvent("SIMILARDOMAIN", r['domain-name'],
                                          self.__name__, event)
                    self.notifyListeners(evt)
            except Exception as e:
                self.error("Couldn't parse the JSON output of DNSTwist: " + str(e))
                return
        except Exception as e:
            self.error("Unable to run DNSTwist: " + str(e))
            return

# End of sfp_tool_dnstwist class
