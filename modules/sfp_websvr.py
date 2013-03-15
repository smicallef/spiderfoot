#-------------------------------------------------------------------------------
# Name:         sfp_websvr
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) and identifying web servers used
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
#-------------------------------------------------------------------------------

import sys
import re
from sflib import SpiderFoot, SpiderFootPlugin

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_websvr(SpiderFootPlugin):
    """Obtain web server banners to identify versions of web servers being used."""

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
        return ["WEBSERVER_HTTPHEADERS"]

    # Handle events sent to this module
    def handleEvent(self, srcModuleName, eventName, eventSource, eventData):
        sf.debug("Received event, " + eventName + ", from " + srcModuleName)
        if self.results.has_key(eventSource):
            return None
        else:
            self.results[eventSource] = True

        if not sf.urlBaseUrl(eventSource).endswith(self.baseDomain):
            sf.debug("Not collecting web server information for external sites.")
            return None

        # Could apply some smarts here, for instance looking for certain
        # banners and therefore classifying them further (type and version,
        # possibly OS. This could also trigger additional tests, such as 404s
        # and other errors to see what the header looks like.
        if eventData.has_key('server'):
            self.notifyListeners("WEBSERVER_BANNER", eventSource, eventData['Server'])
            sf.debug("Found web server: " + eventData['Server'] + " (" + eventSource + ")")

        if (eventData.has_key('x-powered-by')):
            self.notifyListeners("WEBSERVER_TECHNOLOGY", eventSource, eventData['x-powered-by'])
            return None

        if eventData.has_key('set-cookie') and 'PHPSESS' in eventData['set-cookie']:
            self.notifyListeners("WEBSERVER_TECHNOLOGY", eventSource, "PHP")
            return None

        if eventData.has_key('set-cookie') and 'JSESSIONID' in eventData['set-cookie']:
            self.notifyListeners("WEBSERVER_TECHNOLOGY", eventSource, "Java/JSP")
            return None

        if eventData.has_key('set-cookie') and 'ASP.NET' in eventData['set-cookie']:
            self.notifyListeners("WEBSERVER_TECHNOLOGY", eventSource, "ASP.NET")
            return None

        if eventData.has_key('x-aspnet-version'):
            self.notifyListeners("WEBSERVER_TECHNOLOGY", eventSource, "ASP.NET")
            return None

        if '.jsp' in eventSource:
            self.notifyListeners("WEBSERVER_TECHNOLOGY", eventSource, "Java/JSP")
            return None

        if '.php' in eventSource:
            self.notifyListeners("WEBSERVER_TECHNOLOGY", eventSource, "PHP")
            return None

# End of sfp_websvr class

if __name__ == '__main__':
    print "This module cannot be run stand-alone."
    exit(-1)
