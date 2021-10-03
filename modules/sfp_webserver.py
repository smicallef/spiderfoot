# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_webserver
# Purpose:      SpiderFoot plug-in for scanning retrieved content by other
#               modules (such as sfp_spider) and identifying web servers used
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/04/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_webserver(SpiderFootPlugin):

    meta = {
        'name': "Web Server Identifier",
        'summary': "Obtain web server banners to identify versions of web servers being used.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Content Analysis"]
    }

    # Default options
    opts = {}
    optdescs = {}

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["WEBSERVER_HTTPHEADERS"]

    # What events this module produces
    def producedEvents(self):
        return ["WEBSERVER_BANNER", "WEBSERVER_TECHNOLOGY",
                'LINKED_URL_INTERNAL', 'LINKED_URL_EXTERNAL']

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventSource = event.actualSource

        self.debug(f"Received event, {eventName}, from {srcModuleName}")
        if eventSource in self.results:
            return

        self.results[eventSource] = True

        if not self.getTarget().matches(self.sf.urlFQDN(eventSource)):
            self.debug("Not collecting web server information for external sites.")
            return

        try:
            jdata = json.loads(eventData)
            if jdata is None:
                return
        except Exception:
            self.error("Received HTTP headers from another module in an unexpected format.")
            return

        # Check location header for linked URLs
        if 'location' in jdata:
            if jdata['location'].startswith('http://') or jdata['location'].startswith('https://'):
                if self.getTarget().matches(self.sf.urlFQDN(jdata['location'])):
                    evt = SpiderFootEvent('LINKED_URL_INTERNAL', jdata['location'], self.__name__, event)
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent('LINKED_URL_EXTERNAL', jdata['location'], self.__name__, event)
                    self.notifyListeners(evt)

        # Check CSP header for linked URLs
        if 'content-security-policy' in jdata:
            for directive in jdata['content-security-policy'].split(';'):
                for string in directive.split(' '):
                    if string.startswith('http://') or string.startswith('https://'):
                        if self.getTarget().matches(self.sf.urlFQDN(string)):
                            evt = SpiderFootEvent('LINKED_URL_INTERNAL', string, self.__name__, event)
                            self.notifyListeners(evt)
                        else:
                            evt = SpiderFootEvent('LINKED_URL_EXTERNAL', string, self.__name__, event)
                            self.notifyListeners(evt)

        # Could apply some smarts here, for instance looking for certain
        # banners and therefore classifying them further (type and version,
        # possibly OS. This could also trigger additional tests, such as 404s
        # and other errors to see what the header looks like.
        server = jdata.get('server')
        if server:
            self.info(f"Found web server: {server} ({eventSource})")
            evt = SpiderFootEvent("WEBSERVER_BANNER", server, self.__name__, event)
            self.notifyListeners(evt)

        cookies = jdata.get('set-cookie')

        tech = list()

        powered_by = jdata.get('x-powered-by')
        if powered_by:
            tech.append(powered_by)

        if 'x-aspnet-version' in jdata:
            tech.append("ASP.NET")

        if cookies and 'PHPSESS' in cookies:
            tech.append("PHP")

        if cookies and 'JSESSIONID' in cookies:
            tech.append("Java/JSP")

        if cookies and 'ASP.NET' in cookies:
            tech.append("ASP.NET")

        if '.asp' in eventSource:
            tech.append("ASP")

        if '.jsp' in eventSource:
            tech.append("Java/JSP")

        if '.php' in eventSource:
            tech.append("PHP")

        for t in set(tech):
            evt = SpiderFootEvent("WEBSERVER_TECHNOLOGY", t, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_webserver class
