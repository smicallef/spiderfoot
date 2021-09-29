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

import json
import os.path
from subprocess import PIPE, Popen

from spiderfoot import SpiderFootEvent, SpiderFootPlugin, SpiderFootHelpers


class sfp_tool_whatweb(SpiderFootPlugin):

    meta = {
        'name': "Tool - WhatWeb",
        'summary': "Identify what software is in use on the specified website.",
        'flags': ["tool"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Content Analysis"],
        'toolDetails': {
            'name': "WhatWeb",
            'description': "WhatWeb identifies websites. Its goal is to answer the question, \"What is that Website?\". "
            "WhatWeb recognises web technologies including content management systems (CMS), "
            "blogging platforms, statistic/analytics packages, JavaScript libraries, web servers, and embedded devices. "
            "WhatWeb has over 1800 plugins, each to recognise something different. "
            "WhatWeb also identifies version numbers, email addresses, account IDs, web framework modules, SQL errors, and more.",
            'website': 'https://github.com/urbanadventurer/whatweb',
            'repository': 'https://github.com/urbanadventurer/whatweb'
        },
    }

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
        self.results = self.tempStorage()
        self.errorState = False
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return ['INTERNET_NAME']

    def producedEvents(self):
        return ['RAW_RIR_DATA', 'WEBSERVER_BANNER', 'WEBSERVER_TECHNOLOGY']

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

        if not self.opts['whatweb_path']:
            self.error("You enabled sfp_tool_whatweb but did not set a path to the tool!")
            self.errorState = True
            return

        exe = self.opts['whatweb_path']
        if self.opts['whatweb_path'].endswith('/'):
            exe = exe + 'whatweb'

        # If tool is not found, abort
        if not os.path.isfile(exe):
            self.error("File does not exist: " + exe)
            self.errorState = True
            return

        # Sanitize domain name.
        if not SpiderFootHelpers.sanitiseInput(eventData):
            self.error("Invalid input, refusing to run.")
            return

        # Set aggression level
        try:
            aggression = int(self.opts['aggression'])
            if aggression > 4:
                aggression = 4
            if aggression < 1:
                aggression = 1
        except Exception:
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
        except Exception as e:
            self.error(f"Unable to run WhatWeb: {e}")
            return

        if p.returncode != 0:
            self.error("Unable to read WhatWeb output.")
            self.debug("Error running WhatWeb: " + stderr + ", " + stdout)
            return

        if not stdout:
            self.debug(f"WhatWeb returned no output for {eventData}")
            return

        try:
            result_json = json.loads(stdout)
        except Exception as e:
            self.error(f"Couldn't parse the JSON output of WhatWeb: {e}")
            return

        if len(result_json) == 0:
            return

        blacklist = [
            'Country', 'IP',
            'Script', 'Title',
            'HTTPServer', 'RedirectLocation', 'UncommonHeaders', 'Via-Proxy', 'Cookies', 'HttpOnly',
            'Strict-Transport-Security', 'x-hacker', 'x-machine', 'x-pingback', 'X-Backend', 'X-Cache',
            'X-UA-Compatible', 'X-Powered-By', 'X-Forwarded-For', 'X-Frame-Options', 'X-XSS-Protection'
        ]

        found = False
        for result in result_json:
            plugin_matches = result.get('plugins')

            if not plugin_matches:
                continue

            if plugin_matches.get('HTTPServer'):
                for w in plugin_matches.get('HTTPServer').get('string'):
                    evt = SpiderFootEvent('WEBSERVER_BANNER', w, self.__name__, event)
                    self.notifyListeners(evt)
                    found = True

            if plugin_matches.get('X-Powered-By'):
                for w in plugin_matches.get('X-Powered-By').get('string'):
                    evt = SpiderFootEvent('WEBSERVER_TECHNOLOGY', w, self.__name__, event)
                    self.notifyListeners(evt)
                    found = True

            for plugin in plugin_matches:
                if plugin in blacklist:
                    continue
                evt = SpiderFootEvent('WEBSERVER_TECHNOLOGY', plugin, self.__name__, event)
                self.notifyListeners(evt)
                found = True

        if found:
            evt = SpiderFootEvent('RAW_RIR_DATA', str(result_json), self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_tool_whatweb class
