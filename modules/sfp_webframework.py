# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_webframework
# Purpose:      Identify the usage of popular web frameworks.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     25/05/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

regexps = dict({
    "jQuery": list(['jquery']),  # unlikely false positive
    "YUI": list(['\/yui\/', 'yui\-', 'yui\.']),
    "Prototype": list(['\/prototype\/', 'prototype\-', 'prototype\.js']),
    "ZURB Foundation": list(['\/foundation\/', 'foundation\-', 'foundation\.js']),
    "Bootstrap": list(['\/bootstrap\/', 'bootstrap\-', 'bootstrap\.js']),
    "ExtJS": list(['[\'\"\=]ext\.js', 'extjs', '\/ext\/*\.js']),
    "Mootools": list(['\/mootools\/', 'mootools\-', 'mootools\.js']),
    "Dojo": list(['\/dojo\/', '[\'\"\=]dojo\-', '[\'\"\=]dojo\.js']),
    "Wordpress": list(['\/wp-includes\/', '\/wp-content\/'])
})


class sfp_webframework(SpiderFootPlugin):
    """Web Framework:Footprint:Content Analysis::Identify the usage of popular web frameworks like jQuery, YUI and others."""


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
        return ["URL_WEB_FRAMEWORK"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # We only want web content
        if srcModuleName != "sfp_spider":
            return None

        # If you are processing TARGET_WEB_CONTENT, this is how you would get the
        # source of that raw data (e.g. a URL.)
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
                    evt = SpiderFootEvent("URL_WEB_FRAMEWORK", regexpGrp,
                                          self.__name__, event.sourceEvent)
                    self.notifyListeners(evt)

        return None

    # If you intend for this module to act on its own (e.g. not solely rely
    # on events from other modules, then you need to have a start() method
    # and within that method call self.checkForStop() to see if you've been
    # politely asked by the controller to stop your activities (user abort.)

# End of sfp_webframework class
