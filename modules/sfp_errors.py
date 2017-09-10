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

try:
    import re2 as re
except ImportError:
    import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# Taken from Google Dorks on exploit-db.com
regexps = dict({
    "PHP Error": ["PHP pase error", "PHP warning", "PHP error",
                  "unexpected T_VARIABLE", "warning: failed opening", "include_path="],
    "Generic Error": ["Internal Server Error", "Incorrect syntax"],
    "Oracle Error": ["ORA-\d+", "TNS:.?no listen"],
    "ASP Error": ["NET_SessionId"],
    "MySQL Error": ["mysql_query\(", "mysql_connect\("],
    "ODBC Error": ["\[ODBC SQL"]

})


class sfp_errors(SpiderFootPlugin):
    """Errors:Footprint:Content Analysis::Identify common error messages in content like SQL errors, etc."""




    # Default options
    opts = {}

    # Option descriptions
    optdescs = {
        # For each option in opts you should have a key/value pair here
        # describing it. It will end up in the UI to explain the option
        # to the end-user.
    }

    # Target
    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.__dataSource__ = "Target Website"

        for opt in userOpts.keys():
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
            return None

        eventSource = event.sourceEvent.data
        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventSource not in self.results.keys():
            self.results[eventSource] = list()

        # We only want web content for pages on the target site
        if not self.getTarget().matches(self.sf.urlFQDN(eventSource)):
            self.sf.debug("Not collecting web content information for external sites.")
            return None

        for regexpGrp in regexps.keys():
            if regexpGrp in self.results[eventSource]:
                continue

            for regex in regexps[regexpGrp]:
                pat = re.compile(regex, re.IGNORECASE)
                matches = re.findall(pat, eventData)
                if len(matches) > 0 and regexpGrp not in self.results[eventSource]:
                    self.sf.info("Matched " + regexpGrp + " in content from " + eventSource)
                    self.results[eventSource].append(regexpGrp)
                    evt = SpiderFootEvent("ERROR_MESSAGE", regexpGrp,
                                          self.__name__, event.sourceEvent)
                    self.notifyListeners(evt)

        return None

    # If you intend for this module to act on its own (e.g. not solely rely
    # on events from other modules, then you need to have a start() method
    # and within that method call self.checkForStop() to see if you've been
    # politely asked by the controller to stop your activities (user abort.)

# End of sfp_errors class
