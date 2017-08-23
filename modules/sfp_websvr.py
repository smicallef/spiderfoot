# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_websvr
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) and identifying web servers used
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_websvr(SpiderFootPlugin):
    """Web Server:Footprint,Investigate:Content Analysis::Obtain web server banners to identify versions of web servers being used."""


    # Default options
    opts = {}

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.__dataSource__ = "Target Website"

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["WEBSERVER_HTTPHEADERS"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["WEBSERVER_BANNER", "WEBSERVER_TECHNOLOGY"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        parentEvent = event.sourceEvent
        eventSource = event.sourceEvent.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)
        if eventSource in self.results:
            return None
        else:
            self.results[eventSource] = True

        if not self.getTarget().matches(self.sf.urlFQDN(eventSource)):
            self.sf.debug("Not collecting web server information for external sites.")
            return None

        # Could apply some smarts here, for instance looking for certain
        # banners and therefore classifying them further (type and version,
        # possibly OS. This could also trigger additional tests, such as 404s
        # and other errors to see what the header looks like.
        if 'server' in eventData:
            evt = SpiderFootEvent("WEBSERVER_BANNER", eventData['server'],
                                  self.__name__, parentEvent)
            self.notifyListeners(evt)

            self.sf.info("Found web server: " + eventData['server'] + " (" + eventSource + ")")

        if 'x-powered-by' in eventData:
            evt = SpiderFootEvent("WEBSERVER_TECHNOLOGY", eventData['x-powered-by'],
                                  self.__name__, parentEvent)
            self.notifyListeners(evt)
            return None

        tech = None
        if 'set-cookie'in eventData and 'PHPSESS' in eventData['set-cookie']:
            tech = "PHP"

        if 'set-cookie' in eventData and 'JSESSIONID' in eventData['set-cookie']:
            tech = "Java/JSP"

        if 'set-cookie' in eventData and 'ASP.NET' in eventData['set-cookie']:
            tech = "ASP.NET"

        if 'x-aspnet-version' in eventData:
            tech = "ASP.NET"

        if tech is not None and '.jsp' in eventSource:
            tech = "Java/JSP"

        if tech is not None and '.php' in eventSource:
            tech = "PHP"

        if tech is not None:
            evt = SpiderFootEvent("WEBSERVER_TECHNOLOGY", tech, self.__name__, parentEvent)
            self.notifyListeners(evt)

# End of sfp_websvr class
