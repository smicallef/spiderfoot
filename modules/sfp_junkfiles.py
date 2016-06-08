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
import hashlib
import random

class sfp_junkfiles(SpiderFootPlugin):
    """Junk Files:Footprint:Looks for old/temporary and other similar files."""

    # Default options
    opts = {
        'fileexts': ['tmp', 'bak', 'old', 'backup', 'new'],
        'urlextstry': ['html', 'htm', 'php', 'jsp', 'txt', 'js'],
        'files': ['x', 'xxx', 'crap', 'old', 'a', 'aaa', 'z', 'zzz',
                  'out', 'sql', "passwd", ".htaccess", ".htpasswd",
                  "Thumbs.db", "asd", "asdf"],
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

    results = list()
    contentHashes = list()
    hosts = list()
    skiphosts = list()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = list()
        self.contentHashes = list()
        self.hosts = list()
        self.skiphosts = list()

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

    # Check if contents are standard contents
    def isGeneric(self, content):
        hashStr = hashlib.sha1(content.encode('raw_unicode_escape')).hexdigest()
        if hashStr in self.contentHashes:
            self.sf.debug("Skipping due to looking like a generic page.")
            return True
        else:
            self.contentHashes.append(hashStr)
            return False

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
            self.results.append(eventData)

        if host in self.skiphosts:
            return None

        # Try and fetch an obviously missing page, store the hash
        if host not in self.hosts:
            res = self.sf.fetchUrl(host + "/" + str(random.randint(0, 99999999)) + ".html",
                                   timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])
            if res['content'] != None:
                hashStr = hashlib.sha1(res['content'].encode('raw_unicode_escape')).hexdigest()
                self.contentHashes.append(hashStr)  
                if self.opts['skipfake']:
                    self.skiphosts.append(host)
                    return None

            self.hosts.append(host)

        # http://www/blah/abc.html -> try http://www/blah/abc.html.[fileexts]
        for ext in self.opts['urlextstry']:
            if "." + ext + "?" in eventData or "." + ext + "#" in eventData or \
                    eventData.endswith(ext):
                bits = eventData.split("?")
                for x in self.opts['fileexts']:
                    if self.checkForStop():
                        return None

                    self.sf.debug("Trying " + x + " against " + eventData)
                    fetch = bits[0] + "." + x
                    if fetch not in self.results:
                        self.results.append(fetch)
                    else:
                        self.sf.debug("Skipping, already fetched.")
                        continue
                    res = self.sf.fetchUrl(fetch,
                                           timeout=self.opts['_fetchtimeout'],
                                           useragent=self.opts['_useragent'])
                    if res['content'] is not None and res['code'] in ["200", 200]:
                        if not self.isGeneric(res['content']):
                            evt = SpiderFootEvent("JUNK_FILE", fetch,
                                                  self.__name__, event)
                            self.notifyListeners(evt)

        # http://www or http://www/
        # -> try index pages
        if eventData.endswith("/") or eventData.count("/") == 2:
            for ext in ["index.html", "index.htm", "default.htm"]:
                self.sf.debug("Trying " + ext + " against " + eventData)
                for x in self.opts['fileexts']:
                    if self.checkForStop():
                        return None

                    fetch = eventData + "/" + ext + "." + x
                    if fetch not in self.results:
                        self.results.append(fetch)
                    else:
                        self.sf.debug("Skipping, already fetched.")
                        continue
                    res = self.sf.fetchUrl(fetch,
                                           timeout=self.opts['_fetchtimeout'],
                                           useragent=self.opts['_useragent'])
                    if res['content'] is not None and res['code'] in [ "200", 200]:
                        if not self.isGeneric(res['content']):
                            evt = SpiderFootEvent("JUNK_FILE", fetch,
                                                  self.__name__, event)
                            self.notifyListeners(evt)

        base = self.sf.urlBaseDir(eventData)
        # don't do anything with the root directory of a site
        self.sf.debug("Base: " + base + ", event: " + eventData)
        if base == eventData + "/" or base == eventData:
            return None

        # http://www/blah/abc.html -> try http://www/blah.[dirs]
        for dirfile in self.opts['dirs']:
            if self.checkForStop():
                return None

            if base.count('/') < 4:
                self.sf.debug("Skipping base url.")
                continue

            self.sf.debug("Trying " + dirfile + " against " + eventData)
            fetch = base[0:len(base) - 1] + "." + dirfile
            if fetch not in self.results:
                self.results.append(fetch)
            else:
                self.sf.debug("Skipping, already fetched.")
                continue
            res = self.sf.fetchUrl(fetch,
                                   timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])
            if res['content'] is not None and res['code'] in ["200", 200]:
                if not self.isGeneric(res['content']):
                    evt = SpiderFootEvent("JUNK_FILE", fetch,
                                          self.__name__, event)
                    self.notifyListeners(evt)

        # http://www/blah/abc.html -> try http://www/blah/[files]
        for f in self.opts['files']:
            if self.checkForStop():
                return None

            self.sf.debug("Trying " + f + " against " + eventData)
            fetch = base + f
            if fetch not in self.results:
                self.results.append(fetch)
            else:
                self.sf.debug("Skipping, already fetched.")
                continue
            res = self.sf.fetchUrl(fetch,
                                   timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'])
            if res['content'] is not None and res['code'] in ["200", 200]:
                if not self.isGeneric(res['content']):
                    evt = SpiderFootEvent("JUNK_FILE", fetch,
                                          self.__name__, event)
                    self.notifyListeners(evt)

        return None

# End of sfp_junkfiles class
