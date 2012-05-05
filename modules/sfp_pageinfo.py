#-------------------------------------------------------------------------------
# Name:         sfp_pageinfo
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) and building up information about
#               the page, such as whether it uses Javascript plug-ins, has
#               forms, and more.
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

# SpiderFoot standard lib (must be initialized in __init__)
sf = None

# Indentify pages that use Javascript libs, handle passwords, have forms,
# permit file uploads and more to come.
regexps = dict({
    'WEBCONTENT_JAVASCRIPT':  list(['text/javascript', '<script']),
    'WEBCONTENT_FORM':        list(['<form ', 'method=[PG]']),
    'WEBCONTENT_PASSWORD':    list(['type=[\"\']*password']),
    'WEBCONTENT_UPLOAD':      list(['type=[\"\']*file'])
})

results = dict()

class sfp_pageinfo(SpiderFootPlugin):
    # Default options
    opts = {
        # These must always be set
        '_debug':       True,
        '_debugfilter': ''
    }

    # URL this instance is working on
    seedUrl = None
    baseDomain = None # calculated from the URL in __init__

    def __init__(self, url, userOpts=dict()):
        global sf
        self.seedUrl = url

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        # For error reporting, debug, etc.
        sf = SpiderFoot(self.opts)

         # Extract the 'meaningful' part of the FQDN from the URL
        self.baseDomain = sf.urlBaseDom(self.seedUrl)
        sf.debug('Base Domain: ' + self.baseDomain)

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["WEBCONTENT"]

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventData):
        sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventSource not in results.keys():
            results[eventSource] = list()
        else:
            return None

        for regexpGrp in regexps.keys():
            for regex in regexps[regexpGrp]:
                matches = re.findall(regex, eventData, re.IGNORECASE)
                if len(matches) > 0:
                    sf.debug("Matched " + regex + " in content from " + eventSource)
                    self.notifyListeners(regexpGrp, eventSource, eventData)
                    results[eventSource].append(regexpGrp)
                    # Don't bother checking other regexps in this regexp group
                    break

        # If no regexps were matched, consider this a static page
        if len(results[eventSource]) == 0:
            sf.debug("Treating " + eventSource + " as WEBCONTENT_STATIC")
            self.notifyListeners("WEBCONTENT_STATIC", eventSource, eventData)

        return None

# End of sfp_pageinfo class

if __name__ == '__main__':
    print "This module cannot be run stand-alone."
    exit(-1)
