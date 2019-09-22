# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_tool_whatweb
# Purpose:     SpiderFoot plug-in for using the 'WhatWeb' tool.
#              Tool: https://github.com/urbanadventurer/whatweb
#
# Author:      <bcoles@gmail.com>
#
# Created:     2019-08-31
# Copyright:   (c) bcoles 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

from subprocess import Popen, PIPE
import io
import json
import os.path
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_tool_whatweb(SpiderFootPlugin):
    """Tool - WhatWeb:Footprint,Investigate:Content Analysis:tool:Identify what software is in use on the specified website."""

    # Default options
    opts = {
        'aggression': 1,
        'ruby_path': 'ruby',
        'whatweb_path': ''
    }

    # Option descriptions
    optdescs = {
        'aggression': 'Set WhatWeb aggression level (1-4)',
        'ruby_path': "Path to Ruby interpreter to use for WhatWeb. If just 'ruby' then it must be in your $PATH.",
        'whatweb_path': "Path to the whatweb executable file. Must be set."
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
        return ['RAW_RIR_DATA', 'WEBSERVER_BANNER', 'WEBSERVER_TECHNOLOGY']

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

        if not self.opts['whatweb_path']:
            self.sf.error("You enabled sfp_tool_whatweb but did not set a path to the tool!", False)
            self.errorState = True
            return None

        exe = self.opts['whatweb_path']
        if self.opts['whatweb_path'].endswith('/'):
            exe = exe + 'whatweb'

        # If tool is not found, abort
        if not os.path.isfile(exe):
            self.sf.error("File does not exist: " + exe, False)
            self.errorState = True
            return None

        # Sanitize domain name.
        if not self.sf.sanitiseInput(eventData):
            self.sf.error("Invalid input, refusing to run.", False)
            return None

        # Set aggression level
        try:
            aggression = int(self.opts['aggression'])
            if aggression > 4:
                aggression = 4
            if aggression < 1:
                aggression = 1
        except:
            aggression = 1

        # Run WhatWeb
        args = [
            self.opts['ruby_path'],
            exe,
            "--quiet",
            "--aggression=" + str(aggression),
            "--log-json=/dev/stdout",
            "--user-agent=Mozilla/5.0",
            "--follow-redirect=never",
            eventData
        ]
        try:
            p = Popen(args, stdout=PIPE, stderr=PIPE)
            stdout, stderr = p.communicate(input=None)
        except BaseException as e:
            self.sf.error("Unable to run WhatWeb: " + str(e), False)
            return None

        if p.returncode != 0:
            self.sf.error("Unable to read WhatWeb output.", False)
            self.sf.debug("Error running WhatWeb: " + stderr + ", " + stdout)
            return None

        if not stdout:
            self.sf.debug("WhatWeb returned no output for " + eventData)
            return None

        try:
            result_json = json.loads(stdout)
        except BaseException as e:
            self.sf.error("Couldn't parse the JSON output of WhatWeb: " + str(e), False)
            return None

        evt = SpiderFootEvent('RAW_RIR_DATA', str(result_json), self.__name__, event)
        self.notifyListeners(evt)

        blacklist = [
            'Country', 'IP',
            'Script', 'Title',
            'HTTPServer', 'RedirectLocation', 'UncommonHeaders', 'Via-Proxy', 'Cookies', 'HttpOnly',
            'Strict-Transport-Security', 'x-hacker', 'x-machine', 'x-pingback', 'X-Backend', 'X-Cache',
            'X-UA-Compatible', 'X-Powered-By', 'X-Forwarded-For', 'X-Frame-Options', 'X-XSS-Protection'
        ]

        for result in result_json:
            plugin_matches = result.get('plugins')

            if not plugin_matches:
                continue

            if plugin_matches.get('HTTPServer'):
                for w in plugin_matches.get('HTTPServer').get('string'):
                    evt = SpiderFootEvent('WEBSERVER_BANNER', w, self.__name__, event)
                    self.notifyListeners(evt)

            if plugin_matches.get('X-Powered-By'):
                for w in plugin_matches.get('X-Powered-By').get('string'):
                    evt = SpiderFootEvent('WEBSERVER_TECHNOLOGY', w, self.__name__, event)
                    self.notifyListeners(evt)

            for plugin in plugin_matches:
                if plugin in blacklist:
                    continue
                evt = SpiderFootEvent('SOFTWARE_USED', plugin, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_tool_whatweb class
