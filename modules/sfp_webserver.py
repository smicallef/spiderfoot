# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_webserver
# Purpose:      SpiderFoot plug-in for scanning retreived content by other
#               modules (such as sfp_spider) and identifying web servers used
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_webserver(SpiderFootPlugin):
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
        return ["WEBSERVER_BANNER", "WEBSERVER_TECHNOLOGY",
                'LINKED_URL_INTERNAL', 'LINKED_URL_EXTERNAL']

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

        try:
            jdata = json.loads(eventData)
            if jdata == None:
                return None
        except BaseException as e:
            self.sf.error("Received HTTP headers from another module in an unexpected format.", False)
            return None

        # Check location header for linked URLs
        if 'location' in jdata:
            if jdata['location'].startswith('http://') or jdata['location'].startswith('https://'):
                if self.getTarget().matches(self.sf.urlFQDN(jdata['location'])):
                    evt = SpiderFootEvent('LINKED_URL_INTERNAL', jdata['location'], self.__name__, parentEvent)
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent('LINKED_URL_EXTERNAL', jdata['location'], self.__name__, parentEvent)
                    self.notifyListeners(evt)

        # Check CSP header for linked URLs
        if 'content-security-policy' in jdata:
            for directive in jdata['content-security-policy'].split(';'):
                for string in directive.split(' '):
                    if string.startswith('http://') or string.startswith('https://'):
                        if self.getTarget().matches(self.sf.urlFQDN(string)):
                            evt = SpiderFootEvent('LINKED_URL_INTERNAL', string, self.__name__, parentEvent)
                            self.notifyListeners(evt)
                        else:
                            evt = SpiderFootEvent('LINKED_URL_EXTERNAL', string, self.__name__, parentEvent)
                            self.notifyListeners(evt)

        # Could apply some smarts here, for instance looking for certain
        # banners and therefore classifying them further (type and version,
        # possibly OS. This could also trigger additional tests, such as 404s
        # and other errors to see what the header looks like.
        if 'server' in jdata:
            evt = SpiderFootEvent("WEBSERVER_BANNER", jdata['server'],
                                  self.__name__, parentEvent)
            self.notifyListeners(evt)

            self.sf.info("Found web server: " + jdata['server'] + " (" + eventSource + ")")

        if 'x-powered-by' in jdata:
            evt = SpiderFootEvent("WEBSERVER_TECHNOLOGY", jdata['x-powered-by'],
                                  self.__name__, parentEvent)
            self.notifyListeners(evt)
            return None

        tech = None
        if 'set-cookie'in jdata and 'PHPSESS' in jdata['set-cookie']:
            tech = "PHP"

        if 'set-cookie' in jdata and 'JSESSIONID' in jdata['set-cookie']:
            tech = "Java/JSP"

        if 'set-cookie' in jdata and 'ASP.NET' in jdata['set-cookie']:
            tech = "ASP.NET"

        if 'x-aspnet-version' in jdata:
            tech = "ASP.NET"

        if tech is not None and '.jsp' in eventSource:
            tech = "Java/JSP"

        if tech is not None and '.php' in eventSource:
            tech = "PHP"

        if tech is not None:
            evt = SpiderFootEvent("WEBSERVER_TECHNOLOGY", tech, self.__name__, parentEvent)
            self.notifyListeners(evt)

# End of sfp_webserver class
