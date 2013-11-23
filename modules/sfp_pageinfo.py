#-------------------------------------------------------------------------------
# Name:         sfp_pageinfo
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) and building up information about
#               the page, such as whether it uses Javascript, has forms, and more.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     02/05/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

# Indentify pages that use Javascript libs, handle passwords, have forms,
# permit file uploads and more to come.
regexps = dict({
    'URL_JAVASCRIPT':  list(['text/javascript', '<script ']),
    'URL_FORM':        list(['<form ', 'method=[PG]', '<input ']),
    'URL_PASSWORD':    list(['<input.*type=[\"\']*password']),
    'URL_UPLOAD':      list(['type=[\"\']*file']),
    'URL_JAVA_APPLET':     list(['<applet ']),
    'URL_FLASH':    list(['\.swf[ \'\"]'])
})

class sfp_pageinfo(SpiderFootPlugin):
    """Page Info:Obtain information about web pages (do they take passwords, do they contain forms,
etc.)"""

    # Default options
    opts = { }

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
    def watchedEvents(self):
        return ["RAW_DATA"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "URL_STATIC", "URL_JAVASCRIPT", "URL_FORM", "URL_PASSWORD",
            "URL_UPLOAD", "URL_JAVA_APPLET", "URL_FLASH", "PROVIDER_JAVASCRIPT" ]

    # Handle events sent to this module
    def handleEvent(self, event):
        # We are only interested in the raw data from the spidering module
        if "sfp_spider" not in event.module:
            sf.debug("Ignoring RAW_DATA from " + event.module)
            return None

        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventSource = event.sourceEvent.data # will be the URL of the raw data

        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # We aren't interested in describing pages that are not hosted on
        # our base domain.
        if not sf.urlBaseUrl(eventSource).endswith(self.baseDomain):
            sf.debug("Not gathering page info for external site " + eventSource)
            return None

        if eventSource not in self.results.keys():
            self.results[eventSource] = list()
        else:
            sf.debug("Already checked this page for a page type, skipping.")
            return None

        # Check the configured regexps to determine the page type
        for regexpGrp in regexps.keys():
            if regexpGrp in self.results[eventSource]:
                continue

            for regex in regexps[regexpGrp]:
                matches = re.findall(regex, eventData, re.IGNORECASE)
                if len(matches) > 0 and regexpGrp not in self.results[eventSource]:
                    sf.info("Matched " + regexpGrp + " in content from " + eventSource)
                    self.results[eventSource].append(regexpGrp)
                    evt = SpiderFootEvent(regexpGrp, eventSource, self.__name__, event.sourceEvent)
                    self.notifyListeners(evt)

        # If no regexps were matched, consider this a static page
        if len(self.results[eventSource]) == 0:
            sf.info("Treating " + eventSource + " as URL_STATIC")
            evt = SpiderFootEvent("URL_STATIC", eventSource, self.__name__, event.sourceEvent)
            self.notifyListeners(evt)

        # Check for externally referenced Javascript pages
        matches = re.findall("<script.*src=[\'\"]?([^\'\">]*)", eventData, re.IGNORECASE)
        if len(matches) > 0:
            for match in matches:
                if '://' in match and not sf.urlBaseUrl(match).endswith(self.baseDomain):
                    sf.debug("Externally hosted Javascript found at: " + match)
                    evt = SpiderFootEvent("PROVIDER_JAVASCRIPT", match, self.__name__, event.sourceEvent)
                    self.notifyListeners(evt)

        return None

# End of sfp_pageinfo class
