# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tldsearch
# Purpose:      SpiderFoot plug-in for identifying the existence of this target
#               on other TLDs.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     31/08/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

import random
import threading
import time
import dns.resolver
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_tldsearch(SpiderFootPlugin):
    """TLD Searcher:Footprint:DNS:slow:Search all Internet TLDs for domains with the same name as the target (this can be very slow.)"""

    # Default options
    opts = {
        'activeonly': False,  # Only report domains that have content (try to fetch the page)
        'skipwildcards': True,
        '_maxthreads': 50
    }

    # Option descriptions
    optdescs = {
        'activeonly': "Only report domains that have content (try to fetch the page)?",
        "skipwildcards": "Skip TLDs and sub-TLDs that have wildcard DNS."
    }

    # Internal results tracking
    results = None

    # Track TLD search results between threads
    tldResults = dict()
    lock = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.__dataSource__ = "DNS"
        self.lock = threading.Lock()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["SIMILARDOMAIN"]

    def tryTld(self, target, tld):
        resolver = dns.resolver.Resolver()
        resolver.timeout = 1
        resolver.lifetime = 1
        resolver.search = list()
        if self.opts.get('_dnsserver', "") != "":
            resolver.nameservers = [self.opts['_dnsserver']]

        if self.opts['skipwildcards'] and self.sf.checkDnsWildcard(tld):
            return None

        try:
            addrs = self.sf.resolveHost(target)
            if not addrs:
                with self.lock:
                    self.tldResults[target] = False
            else:
                with self.lock:
                    self.tldResults[target] = True
        except BaseException as e:
            with self.lock:
                self.tldResults[target] = False

    def tryTldWrapper(self, tldList, sourceEvent):
        self.tldResults = dict()
        running = True
        i = 0
        t = []

        # Spawn threads for scanning
        self.sf.info("Spawning threads to check TLDs: " + str(tldList))
        for pair in tldList:
            (domain, tld) = pair
            tn = 'thread_sfp_tldsearch_' + str(random.SystemRandom().randint(0, 999999999))
            t.append(threading.Thread(name=tn, target=self.tryTld, args=(domain, tld,)))
            t[i].start()
            i += 1

        # Block until all threads are finished
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("thread_sfp_tldsearch_"):
                    found = True

            if not found:
                running = False

            time.sleep(0.1)

        for res in self.tldResults:
            if self.tldResults[res] and res not in self.results:
                self.sendEvent(sourceEvent, res)

    # Store the result internally and notify listening modules
    def sendEvent(self, source, result):
        self.sf.info("Found a TLD with the target's name: " + result)
        self.results[result] = True

        # Inform listening modules
        if self.opts['activeonly']:
            if self.checkForStop():
                return None

            pageContent = self.sf.fetchUrl('http://' + result,
                                           timeout=self.opts['_fetchtimeout'],
                                           useragent=self.opts['_useragent'],
                                           noLog=True,
                                           verify=False)
            if pageContent['content'] is not None:
                evt = SpiderFootEvent("SIMILARDOMAIN", result, self.__name__, source)
                self.notifyListeners(evt)
        else:
            evt = SpiderFootEvent("SIMILARDOMAIN", result, self.__name__, source)
            self.notifyListeners(evt)

    # Search for similar sounding domains
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        keyword = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
        self.sf.debug("Keyword extracted from " + eventData + ": " + keyword)
        targetList = list()

        if keyword in self.results:
            return None
        else:
            self.results[keyword] = True

        # Look through all TLDs for the existence of this target keyword
        for tld in self.opts['_internettlds']:
            if type(tld) != str:
                tld = str(tld.strip(), errors='ignore')
            else:
                tld = tld.strip()

            if tld.startswith("//") or len(tld) == 0:
                continue

            if tld.startswith("!") or tld.startswith("*") or tld.startswith(".."):
                continue

            if tld.endswith(".arpa"):
                continue

            tryDomain = keyword + "." + tld

            if self.checkForStop():
                return None

            if len(targetList) <= self.opts['_maxthreads']:
                targetList.append([tryDomain, tld])
            else:
                self.tryTldWrapper(targetList, event)
                targetList = list()

        # Scan whatever may be left over.
        if len(targetList) > 0:
            self.tryTldWrapper(targetList, event)

        return None

# End of sfp_tldsearch class
