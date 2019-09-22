# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_archiveorg
# Purpose:      Queries archive.org (Wayback machine) for historic versions of
#               certain pages.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/07/2015
# Copyright:   (c) Steve Micallef 2015
# Licence:     GPL
# -------------------------------------------------------------------------------

import datetime
import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_archiveorg(SpiderFootPlugin):
    """Archive.org:Footprint:Search Engines:slow:Identifies historic versions of interesting files/pages from the Wayback Machine."""


    # Default options
    opts = {
        'farback': "30,60,90",
        'intfiles': True,
        'passwordpages': True,
        'formpages': False,
        'flashpages': False,
        'javapages': False,
        'staticpages': False,
        'uploadpages': False,
        'webframeworkpages': False,
        'javascriptpages': False
    }

    # Option descriptions
    optdescs = {
        'farback': "Number of days back to look for older versions of files/pages in the Wayback Machine snapshots. Comma-separate the values, so for example 30,60,90 means to look for snapshots 30 days, 60 days and 90 days back.",
        'intfiles': "Query the Wayback Machine for historic versions of Interesting Files.",
        'passwordpages': "Query the Wayback Machine for historic versions of URLs with passwords.",
        'formpages': "Query the Wayback Machine for historic versions of URLs with forms.",
        'uploadpages': "Query the Wayback Machine for historic versions of URLs accepting uploads.",
        'flashpages': "Query the Wayback Machine for historic versions of URLs containing Flash.",
        'javapages': "Query the Wayback Machine for historic versions of URLs using Java Applets.",
        'staticpages': "Query the Wayback Machine for historic versions of purely static URLs.",
        "webframeworkpages": "Query the Wayback Machine for historic versions of URLs using Javascript frameworks.",
        "javascriptpages": "Query the Wayback Machine for historic versions of URLs using Javascript."
    }

    results = list()
    foundDates = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()
        self.foundDates = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERESTING_FILE", "URL_PASSWORD", "URL_FORM", "URL_FLASH",
                "URL_STATIC", "URL_JAVA_APPLET", "URL_UPLOAD", "URL_JAVASCRIPT",
                "URL_WEB_FRAMEWORK"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["INTERESTING_FILE_HISTORIC", "URL_PASSWORD_HISTORIC", 
                "URL_FORM_HISTORIC", "URL_FLASH_HISTORIC",
                "URL_STATIC_HISTORIC", "URL_JAVA_APPLET_HISTORIC", 
                "URL_UPLOAD_HISTORIC", "URL_WEB_FRAMEWORK_HISTORIC",
                "URL_JAVASCRIPT_HISTORIC"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventName == "INTERESTING_FILE" and not self.opts['intfiles']:
            return None
        if eventName == "URL_PASSWORD" and not self.opts['passwordpages']:
            return None
        if eventName == "URL_STATIC" and not self.opts['staticpages']:
            return None
        if eventName == "URL_FORM" and not self.opts['formpages']:
            return None
        if eventName == "URL_UPLOAD" and not self.opts['uploadpages']:
            return None
        if eventName == "URL_JAVA_APPLET" and not self.opts['javapages']:
            return None
        if eventName == "URL_FLASH" and not self.opts['flashpages']:
            return None
        if eventName == "URL_JAVASCRIPT" and not self.opts['javascriptpages']:
            return None
        if eventName == "URL_WEB_FRAMEWORK" and not self.opts['webframeworkpages']:
            return None

        if eventData in self.results:
            return None
        else:
            self.results.append(eventData)

        for daysback in self.opts['farback'].split(","):
            newDate = datetime.datetime.now() - datetime.timedelta(days=int(daysback))
            maxDate = newDate.strftime("%Y%m%d")

            url = "https://archive.org/wayback/available?url=" + eventData + \
                  "&timestamp=" + maxDate
            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
                                   useragent=self.opts['_useragent'])

            if res['content'] == None:
                self.sf.error("Unable to fetch " + url, False)
                continue

            try:
                ret = json.loads(res['content'])
            except BaseException as e:
                ret = None

            if ret == None:
                self.sf.error("Unable to process empty response from archive.org: " + \
                              eventData, False)
                continue

            if len(ret['archived_snapshots']) < 1:
                self.sf.debug("No archived snapshots for " + eventData)
                continue

            wbmlink = ret['archived_snapshots']['closest']['url']
            if wbmlink in self.foundDates:
                self.sf.debug("Snapshot already fetched.")
                continue

            self.foundDates.append(wbmlink)
            name = eventName + "_HISTORIC"

            self.sf.info("Found a historic file: " + wbmlink)
            evt = SpiderFootEvent(name, wbmlink, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_archiveorg class
