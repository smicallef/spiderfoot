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

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

regexps = dict({
    "jQuery": list(['jquery']),  # unlikely false positive
    "YUI": list([r'\/yui\/', r'yui\-', r'yui\.']),
    "Prototype": list([r'\/prototype\/', r'prototype\-', r'prototype\.js']),
    "ZURB Foundation": list([r'\/foundation\/', r'foundation\-', r'foundation\.js']),
    "Bootstrap": list([r'\/bootstrap\/', r'bootstrap\-', r'bootstrap\.js']),
    "ExtJS": list([r'[\'\"\=]ext\.js', 'extjs', r'\/ext\/*\.js']),
    "Mootools": list([r'\/mootools\/', r'mootools\-', r'mootools\.js']),
    "Dojo": list([r'\/dojo\/', r'[\'\"\=]dojo\-', r'[\'\"\=]dojo\.js']),
    "Wordpress": list([r'\/wp-includes\/', r'\/wp-content\/'])
})


class sfp_webframework(SpiderFootPlugin):

    meta = {
        'name': "Web Framework Identifier",
        'summary': "Identify the usage of popular web frameworks like jQuery, YUI and others.",
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
        return ["URL_WEB_FRAMEWORK"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventSource = event.actualSource

        # We only want web content
        if srcModuleName != "sfp_spider":
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventSource not in self.results:
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
                    evt = SpiderFootEvent("URL_WEB_FRAMEWORK", regexpGrp,
                                          self.__name__, event)
                    self.notifyListeners(evt)

# End of sfp_webframework class
