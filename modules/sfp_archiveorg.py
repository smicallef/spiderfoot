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

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_archiveorg(SpiderFootPlugin):

    meta = {
        'name': "Archive.org",
        'summary': "Identifies historic versions of interesting files/pages from the Wayback Machine.",
        'flags': ["slow"],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://archive.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://archive.org/projects/",
                "https://archive.org/services/docs/api/"
            ],
            'favIcon': "https://archive.org/images/glogo.jpg",
            'logo': "https://archive.org/images/glogo.jpg",
            'description': "Internet Archive is a non-profit library of millions of free books, movies, software, music, websites, and more.\n"
            "The Internet Archive, a 501(c)(3) non-profit, is building a digital library of Internet sites "
            "and other cultural artifacts in digital form. Like a paper library, we provide free access to "
            "researchers, historians, scholars, the print disabled, and the general public. "
            "Our mission is to provide Universal Access to All Knowledge.\n"
            "We began in 1996 by archiving the Internet itself, a medium that was just beginning to grow in use. "
            "Like newspapers, the content published on the web was ephemeral - but unlike newspapers, no one was saving it. "
            "Today we have 20+ years of web history accessible through the Wayback Machine and we work with 625+ library and "
            "other partners through our Archive-It program to identify important web pages.",
        }

    }

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

    results = None
    foundDates = list()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.foundDates = list()
        self.errorState = False

        for opt in list(userOpts.keys()):
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

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName == "INTERESTING_FILE" and not self.opts['intfiles']:
            return
        if eventName == "URL_PASSWORD" and not self.opts['passwordpages']:
            return
        if eventName == "URL_STATIC" and not self.opts['staticpages']:
            return
        if eventName == "URL_FORM" and not self.opts['formpages']:
            return
        if eventName == "URL_UPLOAD" and not self.opts['uploadpages']:
            return
        if eventName == "URL_JAVA_APPLET" and not self.opts['javapages']:
            return
        if eventName == "URL_FLASH" and not self.opts['flashpages']:
            return
        if eventName == "URL_JAVASCRIPT" and not self.opts['javascriptpages']:
            return
        if eventName == "URL_WEB_FRAMEWORK" and not self.opts['webframeworkpages']:
            return

        if eventData in self.results:
            return

        self.results[eventData] = True

        for daysback in self.opts['farback'].split(","):
            try:
                newDate = datetime.datetime.now() - datetime.timedelta(days=int(daysback))
            except Exception:
                self.error("Unable to parse option for number of days back to search.")
                self.errorState = True
                return

            maxDate = newDate.strftime("%Y%m%d")

            url = "https://archive.org/wayback/available?url=" + eventData + \
                  "&timestamp=" + maxDate
            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])

            if res['content'] is None:
                self.error(f"Unable to fetch {url}")
                continue

            try:
                ret = json.loads(res['content'])
            except Exception as e:
                self.debug(f"Error processing JSON response from Archive.org: {e}")
                ret = None

            if not ret:
                self.debug(f"Empty response from archive.org for {eventData}")
                continue

            if len(ret['archived_snapshots']) < 1:
                self.debug("No archived snapshots for " + eventData)
                continue

            wbmlink = ret['archived_snapshots']['closest']['url']
            if wbmlink in self.foundDates:
                self.debug("Snapshot already fetched.")
                continue

            self.foundDates.append(wbmlink)
            name = eventName + "_HISTORIC"

            self.info("Found a historic file: " + wbmlink)
            evt = SpiderFootEvent(name, wbmlink, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_archiveorg class
