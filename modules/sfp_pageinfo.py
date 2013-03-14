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
from sflib import SpiderFoot, SpiderFootPlugin

# SpiderFoot standard lib (must be initialized in setup)
sf = None

# Indentify pages that use Javascript libs, handle passwords, have forms,
# permit file uploads and more to come.
regexps = dict({
    'WEBCONTENT_JAVASCRIPT':  list(['text/javascript', '<script ']),
    'WEBCONTENT_FORM':        list(['<form ', 'method=[PG]', '<input ']),
    'WEBCONTENT_PASSWORD':    list(['type=[\"\']*password']),
    'WEBCONTENT_UPLOAD':      list(['type=[\"\']*file']),
    'WEBCONTENT_HASJAVA':     list(['<applet ']),
    'WEBCONTENT_HASFLASH':    list(['\.swf[ \'\"]'])
})

class sfp_pageinfo(SpiderFootPlugin):
    """Obtain information about web pages (do they take passwords, do they contain forms,
etc.)"""

    # Default options
    opts = { }

    # URL this instance is working on
    seedUrl = None
    baseDomain = None # calculated from the URL in setup
    results = dict()

    def setup(self, sfc, url, userOpts=dict()):
        global sf

        sf = sfc
        self.seedUrl = url
        self.results = dict()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

         # Extract the 'meaningful' part of the FQDN from the URL
        self.baseDomain = sf.urlBaseDom(self.seedUrl)

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["WEBCONTENT"]

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventData):
        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # We aren't interested in describing pages that are not hosted on
        # our base domain.
        if sf.urlBaseDom(eventSource) != self.baseDomain:
            sf.debug("Not gathering page info for external site " + eventSource)
            return None

        if eventSource not in self.results.keys():
            self.results[eventSource] = list()

        for regexpGrp in regexps.keys():
            if regexpGrp in self.results[eventSource]:
                next

            for regex in regexps[regexpGrp]:
                matches = re.findall(regex, eventData, re.IGNORECASE)
                if len(matches) > 0 and regexpGrp not in self.results[eventSource]:
                    sf.debug("Matched " + regex + " in content from " + eventSource)
                    self.notifyListeners(regexpGrp, eventSource, eventData)
                    self.results[eventSource].append(regexpGrp)

        # If no regexps were matched, consider this a static page
        if len(self.results[eventSource]) == 0:
            sf.debug("Treating " + eventSource + " as WEBCONTENT_STATIC")
            self.notifyListeners("WEBCONTENT_STATIC", eventSource, eventData)

        return None

# End of sfp_pageinfo class

if __name__ == '__main__':
    print "This module cannot be run stand-alone."
    exit(-1)
