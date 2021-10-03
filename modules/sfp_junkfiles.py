# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_junkfiles
# Purpose:      From Spidering, identifies backup and temporary files.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     23/08/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import random

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_junkfiles(SpiderFootPlugin):

    meta = {
        'name': "Junk File Finder",
        'summary': "Looks for old/temporary and other similar files.",
        'flags': ["slow", "errorprone", "invasive"],
        'useCases': ["Footprint"],
        'categories': ["Crawling and Scanning"]
    }

    # Default options
    opts = {
        'fileexts': ['tmp', 'bak', 'old'],
        'urlextstry': ['asp', 'php', 'jsp', ],
        'files': ["old", "passwd", ".htaccess", ".htpasswd",
                  "Thumbs.db", "backup"],
        'dirs': ['zip', 'tar.gz', 'tgz', 'tar']
    }

    # Option descriptions
    optdescs = {
        'fileexts': "File extensions to try.",
        'urlextstry': "Try those extensions against URLs with these extensions.",
        'files': "Try to fetch each of these files from the directory of the URL.",
        'dirs': "Try to fetch the containing folder with these extensions."
    }

    results = None
    hosts = None
    skiphosts = None
    bases = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.hosts = self.tempStorage()
        self.skiphosts = self.tempStorage()
        self.bases = self.tempStorage()
        self.__dataSource__ = "Target Website"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["LINKED_URL_INTERNAL"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["JUNK_FILE"]

    # Test how trustworthy a result is
    def checkValidity(self, junkUrl):
        # Try and fetch an obviously missing version of the junk file
        fetch = junkUrl + str(random.SystemRandom().randint(0, 99999999))
        res = self.sf.fetchUrl(fetch, headOnly=True,
                               timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'],
                               verify=False)
        if res['code'] != "404":
            host = self.sf.urlBaseUrl(junkUrl)
            self.skiphosts[host] = True
            return False
        return True

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            return

        self.results[eventData] = True

        host = self.sf.urlBaseUrl(eventData)

        if host in self.skiphosts:
            self.debug("Skipping " + host + " because it doesn't return 404s.")
            return

        # http://www/blah/abc.php -> try http://www/blah/abc.php.[fileexts]
        for ext in self.opts['urlextstry']:
            if host in self.skiphosts:
                self.debug("Skipping " + host + " because it doesn't return 404s.")
                return

            if "." + ext + "?" in eventData or "." + ext + "#" in eventData or \
                    eventData.endswith("." + ext):
                bits = eventData.split("?")
                for x in self.opts['fileexts']:
                    if self.checkForStop():
                        return

                    self.debug("Trying " + x + " against " + eventData)
                    fetch = bits[0] + "." + x
                    if fetch in self.results:
                        self.debug("Skipping, already fetched.")
                        continue

                    self.results[fetch] = True

                    res = self.sf.fetchUrl(fetch, headOnly=True,
                                           timeout=self.opts['_fetchtimeout'],
                                           useragent=self.opts['_useragent'],
                                           sizeLimit=10000000,
                                           verify=False)
                    if res['realurl'] != fetch:
                        self.debug("Skipping because " + res['realurl'] + " isn't the fetched URL of " + fetch)
                        continue
                    if res['code'] == "200":
                        if not self.checkValidity(fetch):
                            continue

                        evt = SpiderFootEvent("JUNK_FILE", fetch, self.__name__, event)
                        self.notifyListeners(evt)

        base = self.sf.urlBaseDir(eventData)
        if not base or base in self.bases:
            return

        self.bases[base] = True

        # http://www/blah/abc.html -> try http://www/blah/[files]
        for f in self.opts['files']:
            if self.checkForStop():
                return

            if host in self.skiphosts:
                self.debug("Skipping " + host + " because it doesn't return 404s.")
                return

            self.debug("Trying " + f + " against " + eventData)
            fetch = base + f
            if fetch in self.results:
                self.debug("Skipping, already fetched.")
                continue

            self.results[fetch] = True

            res = self.sf.fetchUrl(fetch, headOnly=True,
                                   timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'],
                                   verify=False)
            if res['realurl'] != fetch:
                self.debug("Skipping because " + res['realurl'] + " isn't the fetched URL of " + fetch)
                continue
            if res['code'] == "200":
                if not self.checkValidity(fetch):
                    continue

                evt = SpiderFootEvent("JUNK_FILE", fetch, self.__name__, event)
                self.notifyListeners(evt)

        # don't do anything with the root directory of a site
        self.debug(f"Base: {base}, event: {eventData}")
        if base in [eventData, eventData + "/"]:
            return

        # http://www/blah/abc.html -> try http://www/blah.[dirs]
        for dirfile in self.opts['dirs']:
            if self.checkForStop():
                return

            if host in self.skiphosts:
                self.debug("Skipping " + host + " because it doesn't return 404s.")
                return

            if base.count('/') == 3:
                self.debug("Skipping base url.")
                continue

            self.debug("Trying " + dirfile + " against " + eventData)
            fetch = base[0:len(base) - 1] + "." + dirfile
            if fetch in self.results:
                self.debug("Skipping, already fetched.")
                continue

            self.results[fetch] = True

            res = self.sf.fetchUrl(fetch, headOnly=True,
                                   timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'],
                                   verify=False)
            if res['realurl'] != fetch:
                self.debug("Skipping because " + res['realurl'] + " isn't the fetched URL of " + fetch)
                continue
            if res['code'] == "200":
                if not self.checkValidity(fetch):
                    continue

                evt = SpiderFootEvent("JUNK_FILE", fetch, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_junkfiles class
