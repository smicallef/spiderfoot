#-------------------------------------------------------------------------------
# Name:         sfp_tldsearch
# Purpose:      SpiderFoot plug-in for identifying the existence of this target
#               on other TLDs.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     31/08/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
#-------------------------------------------------------------------------------

import dns.resolver
import socket
import sys
import re
import time
import random
import threading
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

# SpiderFoot standard lib (must be initialized in setup)
sf = None

class sfp_tldsearch(SpiderFootPlugin):
    """TLD Search:Search all Internet TLDs for domains with the same name as the target."""

    # Default options
    opts = {
        'activeonly':   True, # Only report domains that have content (try to fetch the page)
        'skipwildcards':    True,
        'maxthreads':   100
    }

    # Option descriptions
    optdescs = {
        'activeonly':   "Only report domains that have content (try to fetch the page)?",
        "skipwildcards":    "Skip TLDs and sub-TLDs that have wildcard DNS.",
        "maxthreads":   "Number of simultaneous DNS resolutions to perform at once."
    }

    # Internal results tracking
    results = list()

    # Target
    baseDomain = None

    # Track TLD search results between threads
    tldResults = dict()

    def setup(self, sfc, target, userOpts=dict()):
        global sf

        sf = sfc
        self.baseDomain = target
        self.results = list()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return None

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return [ "SIMILARDOMAIN" ]

    def tryTld(self, target):
        try:
            addrs = socket.gethostbyname_ex(target)
            self.tldResults[target] = True
        except BaseException as e:
            self.tldResults[target] = False

    def tryTldWrapper(self, tldList):
        self.tldResults = dict()
        running = True
        i = 0
        t = []

        # Spawn threads for scanning
        sf.info("Spawning threads to check TLDs: " + str(tldList))
        for tld in tldList:
            t.append(threading.Thread(name='sfp_tldsearch_' + tld,
                target=self.tryTld, args=(tld,)))
            t[i].start()
            i += 1

        # Block until all threads are finished
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("sfp_tldsearch_"):
                    found = True

            if not found:
                running = False

        for res in self.tldResults.keys():
            if self.tldResults[res]:
                self.sendEvent(None, res)

    # Store the result internally and notify listening modules
    def sendEvent(self, source, result):
        if result == self.baseDomain:
            return

        sf.info("Found a TLD with the target's name: " + result)
        self.results.append(result)

        # Inform listening modules
        if self.opts['activeonly']:
            if self.checkForStop():
                return None

            pageContent = sf.fetchUrl('http://' + result,
                timeout=self.opts['_fetchtimeout'], useragent=self.opts['_useragent'])
            if pageContent['content'] != None:
                evt = SpiderFootEvent("SIMILARDOMAIN", result, self.__name__)
                self.notifyListeners(evt)
        else:
            evt = SpiderFootEvent("SIMILARDOMAIN", result, self.__name__)
            self.notifyListeners(evt)

    # Search for similar sounding domains
    def start(self):
        keyword = sf.domainKeyword(self.baseDomain)
        sf.debug("Keyword extracted from " + self.baseDomain + ": " + keyword)
        targetList = list()

        # Look through all TLDs for the existence of this target keyword
        for tld in self.opts['_internettlds']:
            tld = unicode(tld.strip(), errors='ignore')

            if tld.startswith("//") or len(tld) == 0:
                continue

            if tld.startswith("!") or tld.startswith("*") or tld.startswith(".."):
                continue

            if tld.endswith(".arpa"):
                continue

            if self.opts['skipwildcards'] and sf.checkDnsWildcard(tld):
                continue

            tryDomain = keyword + "." + tld

            if self.checkForStop():
                return None

            if len(targetList) <= self.opts['maxthreads']:
                targetList.append(tryDomain)
            else:
                self.tryTldWrapper(targetList)
                targetList = list()

        # Scan whatever may be left over.
        if len(targetList) > 0:
            self.tryTldWrapper(targetList)

        return None

# End of sfp_tldsearch class
