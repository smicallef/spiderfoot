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

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
import random

class sfp_junkfiles(SpiderFootPlugin):
    """Junk Files:Footprint:Crawling and Scanning:slow,errorprone,invasive:Looks for old/temporary and other similar files."""


    # Default options
    opts = {
        'fileexts': ['tmp', 'bak', 'old'],
        'urlextstry': ['asp', 'php', 'jsp',],
        'files': ["old", "passwd", ".htaccess", ".htpasswd",
                  "Thumbs.db", "backup"],
        'dirs': ['zip', 'tar.gz', 'tgz', 'tar'],
        'skipfake': True
    }

    # Option descriptions
    optdescs = {
        'fileexts': "File extensions to try.",
        'urlextstry': "Try those extensions against URLs with these extensions.",
        'files': "Try to fetch each of these files from the directory of the URL.",
        'dirs': "Try to fetch the containing folder with these extensions.",
        'skipfake': "Try to fetch an obviously fake page and if no 404 is returned, stop trying that particular host for junk files. Good for avoiding false positives in cases where servers return content for pages that don't exist."
    }

    results = dict()
    hosts = dict()
    skiphosts = dict()
    bases = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.hosts = dict()
        self.skiphosts = dict()
        self.bases = dict()
        self.__dataSource__ = "Target Website"

        for opt in userOpts.keys():
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
                               useragent=self.opts['_useragent'])
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
        host = self.sf.urlBaseUrl(eventData)

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        if self.opts['skipfake'] and host in self.skiphosts:
            self.sf.debug("Skipping " + host + " because it doesn't return 404s.")
            return None

        # http://www/blah/abc.php -> try http://www/blah/abc.php.[fileexts]
        for ext in self.opts['urlextstry']:
            if self.opts['skipfake'] and host in self.skiphosts:
                self.sf.debug("Skipping " + host + " because it doesn't return 404s.")
                return None
 
            if "." + ext + "?" in eventData or "." + ext + "#" in eventData or \
                    eventData.endswith("." + ext):
                bits = eventData.split("?")
                for x in self.opts['fileexts']:
                    if self.checkForStop():
                        return None

                    self.sf.debug("Trying " + x + " against " + eventData)
                    fetch = bits[0] + "." + x
                    if fetch not in self.results:
                        self.results[fetch] = True
                    else:
                        self.sf.debug("Skipping, already fetched.")
                        continue
                    res = self.sf.fetchUrl(fetch, headOnly=True,
                                           timeout=self.opts['_fetchtimeout'],
                                           useragent=self.opts['_useragent'],
                                           sizeLimit=10000000)
                    if res['realurl'] != fetch:
                        self.sf.debug("Skipping because " + res['realurl'] + " isn't the fetched URL of " + fetch)
                        continue
                    if res['code'] == "200":
                        if not self.checkValidity(fetch):
                            continue

                        evt = SpiderFootEvent("JUNK_FILE", fetch, self.__name__, event)
                        self.notifyListeners(evt)

        base = self.sf.urlBaseDir(eventData)
        if base in self.bases:
            return None
        else:
            self.bases[base] = True

        # don't do anything with the root directory of a site
        self.sf.debug("Base: " + base + ", event: " + eventData)
        if base == eventData + "/" or base == eventData:
            return None

        # http://www/blah/abc.html -> try http://www/blah.[dirs]
        for dirfile in self.opts['dirs']:
            if self.checkForStop():
                return None

            if self.opts['skipfake'] and host in self.skiphosts:
                self.sf.debug("Skipping " + host + " because it doesn't return 404s.")
                return None

            if base.count('/') == 3:
                self.sf.debug("Skipping base url.")
                continue

            self.sf.debug("Trying " + dirfile + " against " + eventData)
            fetch = base[0:len(base) - 1] + "." + dirfile
            if fetch not in self.results:
                self.results[fetch] = True
            else:
                self.sf.debug("Skipping, already fetched.")
                continue
            res = self.sf.fetchUrl(fetch, headOnly=True,
                                   timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])
            if res['realurl'] != fetch:
                self.sf.debug("Skipping because " + res['realurl'] + " isn't the fetched URL of " + fetch)
                continue
            if res['code'] == "200":
                if not self.checkValidity(fetch):
                    continue

                evt = SpiderFootEvent("JUNK_FILE", fetch, self.__name__, event)
                self.notifyListeners(evt)

        # http://www/blah/abc.html -> try http://www/blah/[files]
        for f in self.opts['files']:
            if self.checkForStop():
                return None

            if self.opts['skipfake'] and host in self.skiphosts:
                self.sf.debug("Skipping " + host + " because it doesn't return 404s.")
                return None

            self.sf.debug("Trying " + f + " against " + eventData)
            fetch = base + f
            if fetch not in self.results:
                self.results[fetch] = True
            else:
                self.sf.debug("Skipping, already fetched.")
                continue
            res = self.sf.fetchUrl(fetch, headOnly=True,
                                   timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])
            if res['realurl'] != fetch:
                self.sf.debug("Skipping because " + res['realurl'] + " isn't the fetched URL of " + fetch)
                continue
            if res['code'] == "200":
                if not self.checkValidity(fetch):
                    continue

                evt = SpiderFootEvent("JUNK_FILE", fetch, self.__name__, event)
                self.notifyListeners(evt)

        return None

# End of sfp_junkfiles class
