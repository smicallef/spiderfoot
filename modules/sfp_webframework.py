#-------------------------------------------------------------------------------
# Name:         sfp_webframework
# Purpose:      Identify the usage of popular web frameworks.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     25/05/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
#-------------------------------------------------------------------------------

import re
import sys
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

regexps = dict({
    "jQuery":           list(['jquery']), # unlikely false positive
    "YUI":              list(['\/yui\/', 'yui\-', 'yui\.']),
    "Prototype":        list(['\/prototype\/', 'prototype\-', 'prototype\.js']),
    "ZURB Foundation":  list(['\/foundation\/', 'foundation\-', 'foundation\.js']),
    "Bootstrap":        list(['\/bootstrap\/', 'bootstrap\-', 'bootstrap\.js']),
    "ExtJS":            list(['[\'\"\=]ext\.js', 'extjs', '\/ext\/*\.js']),
    "Mootools":         list(['\/mootools\/', 'mootools\-', 'mootools\.js']),
    "Dojo":             list(['\/dojo\/', '[\'\"\=]dojo\-', '[\'\"\=]dojo\.js'])
})

class sfp_webframework(SpiderFootPlugin):
    """Identify the usage of popular web frameworks like jQuery, YUI and others."""

    # Default options
    opts = { }

    # Option descriptions
    optdescs = {
        # For each option in opts you should have a key/value pair here
        # describing it. It will end up in the UI to explain the option
        # to the end-user.
    }

    # Target
    baseDomain = None # calculated from the URL in setup
    results = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # * = be notified about all events.
    def watchedEvents(self):
        return ["RAW_DATA"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # We only want web content
        if srcModuleName != "sfp_spider":
            return None

        # If you are processing RAW_DATA, this is how you would get the
        # source of that raw data (e.g. a URL.)
        eventSource = event.sourceEvent.data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventSource not in self.results.keys():
            self.results[eventSource] = list()

        # We only want web content for pages on the target site
        if not sf.urlBaseUrl(eventSource).endswith(self.baseDomain):
            sf.debug("Not collecting web content information for external sites.")
            return None

        for regexpGrp in regexps.keys():
            if regexpGrp in self.results[eventSource]:
                continue

            for regex in regexps[regexpGrp]:
                matches = re.findall(regex, eventData, re.IGNORECASE)
                if len(matches) > 0 and regexpGrp not in self.results[eventSource]:
                    sf.info("Matched " + regexpGrp + " in content from " + eventSource)
                    self.results[eventSource].append(regexpGrp)
                    evt = SpiderFootEvent("URL_JAVASCRIPT_FRAMEWORK", regexpGrp, 
                        self.__name__, event.sourceEvent)
                    self.notifyListeners(evt)

        return None

    # If you intend for this module to act on its own (e.g. not solely rely
    # on events from other modules, then you need to have a start() method
    # and within that method call self.checkForStop() to see if you've been
    # politely asked by the controller to stop your activities (user abort.)

# End of sfp_webframework class
