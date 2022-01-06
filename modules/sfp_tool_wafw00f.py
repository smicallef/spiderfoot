# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_wafw00f
# Purpose:     SpiderFoot plug-in for using the WAFW00F tool.
#              Tool: https://github.com/EnableSecurity/wafw00f
#
# Author:      <bcoles@gmail.com>
#
# Created:     2021-03-10
# Copyright:   (c) bcoles 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import os.path
from subprocess import PIPE, Popen

from spiderfoot import SpiderFootEvent, SpiderFootPlugin, SpiderFootHelpers


class sfp_tool_wafw00f(SpiderFootPlugin):
    meta = {
        'name': "Tool - WAFW00F",
        'summary': "Identify what web application firewall (WAF) is in use on the specified website.",
        'flags': ["tool"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "WAFW00F",
            'description': "WAFW00F allows one to identify and fingerprint Web Application Firewall (WAF) products protecting a website.",
            'website': 'https://github.com/EnableSecurity/wafw00f',
            'repository': 'https://github.com/EnableSecurity/wafw00f'
        },
    }

    opts = {
        'python_path': 'python3',
        'wafw00f_path': ''
    }

    optdescs = {
        'python_path': "Path to Python 3 interpreter to use for wafw00f. If just 'python3' then it must be in your $PATH.",
        'wafw00f_path': "Path to the wafw00f executable file. Must be set."
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
        return ['RAW_RIR_DATA', 'WEBSERVER_TECHNOLOGY']

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

        if not self.opts['wafw00f_path']:
            self.error("You enabled sfp_tool_wafw00f but did not set a path to the tool!")
            self.errorState = True
            return

        exe = self.opts['wafw00f_path']
        if self.opts['wafw00f_path'].endswith('/'):
            exe = exe + 'wafw00f'

        if not os.path.isfile(exe):
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        url = eventData

        if not SpiderFootHelpers.sanitiseInput(url):
            self.error("Invalid input, refusing to run.")
            return

        args = [
            self.opts['python_path'],
            exe,
            '-a',
            '-o-',
            '-f',
            'json',
            url
        ]
        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None)
        except Exception as e:
            self.error(f"Unable to run wafw00f: {e}")
            return

        if p.returncode != 0:
            self.error(f"Unable to read wafw00f output\nstderr: {stderr}\nstdout: {stdout}")
            return

        if not stdout:
            self.debug(f"wafw00f returned no output for {eventData}")
            return

        try:
            result_json = json.loads(stdout)
        except Exception as e:
            self.error(f"Could not parse wafw00f output as JSON: {e}\nstdout: {stdout}")
            return

        if not result_json:
            self.debug(f"wafw00f returned no output for {eventData}")
            return

        evt = SpiderFootEvent('RAW_RIR_DATA', json.dumps(result_json), self.__name__, event)
        self.notifyListeners(evt)

        for waf in result_json:
            if not waf:
                continue

            firewall = waf.get('firewall')
            if not firewall:
                continue
            if firewall == 'Generic':
                continue

            manufacturer = waf.get('manufacturer')
            if not manufacturer:
                continue

            software = ' '.join(filter(None, [manufacturer, firewall]))

            if software:
                evt = SpiderFootEvent('WEBSERVER_TECHNOLOGY', software, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_tool_wafw00f class
