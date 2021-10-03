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

import io
import json
import os.path
from subprocess import PIPE, Popen

from spiderfoot import SpiderFootEvent, SpiderFootPlugin, SpiderFootHelpers


class sfp_tool_cmseek(SpiderFootPlugin):

    meta = {
        'name': "Tool - CMSeeK",
        'summary': "Identify what Content Management System (CMS) might be used.",
        'flags': ["tool"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Content Analysis"],
        'toolDetails': {
            'name': "CMSeeK",
            'description': "CMSeek is a tool that is used to extract Content Management System(CMS) details of a website.",
            'website': 'https://github.com/Tuhinshubhra/CMSeeK',
            'repository': 'https://github.com/Tuhinshubhra/CMSeeK'
        },
    }

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
        self.results = self.tempStorage()
        self.errorState = False
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
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

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData} as already scanned.")
            return

        self.results[eventData] = True

        if not self.opts['cmseekpath']:
            self.error("You enabled sfp_tool_cmseek but did not set a path to the tool!")
            self.errorState = True
            return

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
            self.error(f"File does not exist: {exe}")
            self.errorState = True
            return

        # Sanitize domain name.
        if not SpiderFootHelpers.sanitiseInput(eventData):
            self.error("Invalid input, refusing to run.")
            return

        args = [
            self.opts['pythonpath'],
            exe,
            '--follow-redirect',
            '--batch',
            '-u',
            eventData
        ]
        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None)
        except Exception as e:
            self.error(f"Unable to run CMSeeK: {e}")
            return

        if p.returncode != 0:
            self.error(f"Unable to read CMSeeK output\nstderr: {stderr}\nstdout: {stdout}")
            return

        if b"CMS Detection failed" in stdout:
            self.debug(f"Could not detect the CMS for {eventData}")
            return

        log_path = f"{resultpath}/{eventData}/cms.json"
        if not os.path.isfile(log_path):
            self.error(f"File does not exist: {log_path}")
            return

        try:
            f = io.open(log_path, encoding='utf-8')
            j = json.loads(f.read())
        except Exception as e:
            self.error(f"Could not parse CMSeeK output file {log_path} as JSON: {e}")
            return

        cms_name = j.get('cms_name')

        if not cms_name:
            return

        cms_version = j.get('cms_version')

        software = ' '.join(filter(None, [cms_name, cms_version]))

        if not software:
            return

        evt = SpiderFootEvent("WEBSERVER_TECHNOLOGY", software, self.__name__, event)
        self.notifyListeners(evt)

# End of sfp_tool_cmseek class
