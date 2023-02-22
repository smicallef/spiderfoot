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
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
from pathlib import Path
from shutil import which
from subprocess import PIPE, Popen, TimeoutExpired

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
        'dnstwistpath': "",
        'skipwildcards': True
    }

    # Option descriptions
    optdescs = {
        'pythonpath': "Path to Python interpreter to use for DNSTwist. If just 'python' then it must be in your PATH.",
        'dnstwistpath': "Path to the where the dnstwist.py file lives. Optional.",
        'skipwildcards': "Skip TLDs and sub-TLDs that have wildcard DNS."
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
            self.debug(f"Skipping {eventData} as already scanned.")
            return

        self.results[eventData] = True

        # Sanitize domain name
        if not SpiderFootHelpers.sanitiseInput(eventData):
            self.error("Invalid input, refusing to run.")
            return

        dom = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
        if not dom:
            self.error(f"Could not extract keyword from domain: {eventData}")
            return

        tld = eventData.split(dom + ".")[-1]
        # Check if the TLD has wildcards before testing
        if self.opts['skipwildcards'] and self.sf.checkDnsWildcard(tld):
            self.debug(f"Wildcard DNS detected on {eventData} TLD: {tld}")
            return

        # TODO: check dnstwistpath option before trying which()
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

        try:
            p = Popen(cmd + ["-f", "json", "-r", eventData], stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None, timeout=300)
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
                    # Support different formats from DNStwist versions
                    domain = r.get('domain-name')
                    if not domain:
                        domain = r.get('domain')
                    if self.getTarget().matches(domain, includeParents=True):
                        continue

                    evt = SpiderFootEvent("SIMILARDOMAIN", domain,
                                          self.__name__, event)
                    self.notifyListeners(evt)
            except Exception as e:
                self.error("Couldn't parse the JSON output of DNSTwist: " + str(e))
                return
        except TimeoutExpired:
            p.kill()
            stdout, stderr = p.communicate()
            self.debug(f"Timed out waiting for DNSTwist to finish on {eventData}")
            return
        except Exception as e:
            self.error("Unable to run DNSTwist: " + str(e))
            return

# End of sfp_tool_dnstwist class
