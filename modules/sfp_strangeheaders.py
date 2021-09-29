# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_strangeheaders
# Purpose:      SpiderFoot plug-in for identifying non-standard HTTP headers
#               in web server responses.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     01/12/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import json

from spiderfoot import SpiderFootEvent, SpiderFootPlugin

# Standard headers, taken from http://en.wikipedia.org/wiki/List_of_HTTP_header_fields
headers = [
    "accept-patch",
    "accept-ranges",
    "access-control-allow-credentials",
    "access-control-allow-headers",
    "access-control-allow-methods",
    "access-control-allow-origin",
    "access-control-expose-headers",
    "access-control-max-age",
    "age",
    "allow",
    "alt-svc",
    "cache-control",
    "connection",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-length",
    "content-location",
    "content-md5",
    "content-range",
    "content-security-policy",
    "content-type",
    "date",
    "delta-base",
    "etag",
    "expires",
    "im",
    "last-modified",
    "link",
    "location",
    "p3p",
    "pragma",
    "proxy-authenticate",
    "public-key-pins",
    "refresh",
    "retry-after",
    "server",
    "set-cookie",
    "status",
    "strict-transport-security",
    "timing-allow-origin",
    "tk",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "vary",
    "via",
    "warning",
    "www-authenticate",
    "x-content-duration",
    "x-content-security-policy",
    "x-content-type-options",
    "x-correlation-id",
    "x-frame-options",
    "x-powered-by",
    "x-request-id",
    "x-ua-compatible",
    "x-webkit-csp",
    "x-xss-protection",
]


class sfp_strangeheaders(SpiderFootPlugin):

    meta = {
        'name': "Strange Header Identifier",
        'summary': "Obtain non-standard HTTP headers returned by web servers.",
        'flags': [],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Content Analysis"]
    }

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
        return ["WEBSERVER_STRANGEHEADER"]

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

        fqdn = self.sf.urlFQDN(eventSource)
        if not self.getTarget().matches(fqdn):
            self.debug(f"Not collecting header information for external sites. Ignoring HTTP headers from {fqdn}")
            return

        try:
            data = json.loads(eventData)
        except Exception:
            self.error("Received HTTP headers from another module in an unexpected format.")
            return

        for key in data:
            if key.lower() not in headers:
                evt = SpiderFootEvent("WEBSERVER_STRANGEHEADER", f"{key}: {data[key]}", self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_strangeheaders class
