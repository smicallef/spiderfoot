# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_errors
# Purpose:      Identify common error messages in content like SQL errors, etc.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     18/01/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import re

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

# Taken from Google Dorks on exploit-db.com
regexps = dict({
    "PHP Error": ["PHP pase error", "PHP warning", "PHP error",
                  "unexpected T_VARIABLE", "warning: failed opening", "include_path="],
    "Generic Error": ["Internal Server Error", "Incorrect syntax"],
    "Oracle Error": [r"ORA-\d+", "TNS:.?no listen"],
    "ASP Error": ["NET_SessionId"],
    "MySQL Error": [r"mysql_query\(", r"mysql_connect\("],
    "ODBC Error": [r"\[ODBC SQL"]

})


class sfp_errors(SpiderFootPlugin):

    meta = {
        'name': "Error String Extractor",
        'summary': "Identify common error messages in content like SQL errors, etc.",
        'flags': [],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Content Analysis"]
    }

    # Default options
    opts = {}

    # Option descriptions
    optdescs = {
        # For each option in opts you should have a key/value pair here
        # describing it. It will end up in the UI to explain the option
        # to the end-user.
    }

    # Target
    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["TARGET_WEB_CONTENT"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["ERROR_MESSAGE"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # We only want web content from the target
        if srcModuleName != "sfp_spider":
            return

        eventSource = event.actualSource

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventSource not in list(self.results.keys()):
            self.results[eventSource] = list()

        # We only want web content for pages on the target site
        if not self.getTarget().matches(self.sf.urlFQDN(eventSource)):
            self.debug("Not collecting web content information for external sites.")
            return

        for regexpGrp in list(regexps.keys()):
            if regexpGrp in self.results[eventSource]:
                continue

            for regex in regexps[regexpGrp]:
                pat = re.compile(regex, re.IGNORECASE)
                matches = re.findall(pat, eventData)
                if len(matches) > 0 and regexpGrp not in self.results[eventSource]:
                    self.info("Matched " + regexpGrp + " in content from " + eventSource)
                    self.results[eventSource] = self.results[eventSource] + [regexpGrp]
                    evt = SpiderFootEvent("ERROR_MESSAGE", regexpGrp,
                                          self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_errors class
