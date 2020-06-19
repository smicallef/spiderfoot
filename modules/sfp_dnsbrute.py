# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dnsbrute
# Purpose:      SpiderFoot plug-in for attempting to resolve through brute-forcing
#               common hostnames.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     06/07/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import random
import threading
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_dnsbrute(SpiderFootPlugin):
    """DNS Brute-forcer:Footprint,Investigate:DNS::Attempts to identify hostnames through brute-forcing common names and iterations."""


    # Default options
    opts = {
        "skipcommonwildcard": True,
        "domainonly": True,
        "commons": True,
        "top10000": False,
        "numbersuffix": True,
        "numbersuffixlimit": True,
        "_maxthreads": 100
    }

    # Option descriptions
    optdescs = {
        'skipcommonwildcard': "If wildcard DNS is detected, don't bother brute-forcing.",
        'domainonly': "Only attempt to brute-force names on domain names, not hostnames (some hostnames are also sub-domains).",
        'commons': "Try a list of about 750 common hostnames/sub-domains.",
        'top10000': "Try a further 10,000 common hostnames/sub-domains. Will make the scan much slower.",
        'numbersuffix': "For any host found, try appending 1, 01, 001, -1, -01, -001, 2, 02, etc. (up to 10)",
        'numbersuffixlimit': "Limit using the number suffixes for hosts that have already been resolved? If disabled this will significantly extend the duration of scans."
    }

    events = None
    sublist = None
    lock = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.sublist = self.tempStorage()
        self.events = self.tempStorage()
        self.__dataSource__ = "DNS"
        self.lock = threading.Lock()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

        cslines = list()
        if self.opts['commons']:
            cs = open(self.sf.myPath() + "/dicts/subdomains.txt", 'r')
            cslines = cs.readlines()
            for s in cslines:
                s = s.strip()
                self.sublist[s] = True

        ttlines = list()
        if self.opts['top10000']:
            tt = open(self.sf.myPath() + "/dicts/subdomains-10000.txt", 'r')
            ttlines = tt.readlines()
            for s in ttlines:
                s = s.strip()
                self.sublist[s] = True

    # What events is this module interested in for input
    def watchedEvents(self):
        ret = ['DOMAIN_NAME']
        if not self.opts['domainonly'] or self.opts['numbersuffix']:
            ret.append('INTERNET_NAME')
        return ret

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["INTERNET_NAME"]

    def tryHost(self, name):
        try:
            addrs = self.sf.resolveHost(name)
            if addrs:
                with self.lock:
                    self.hostResults[name] = True
        except BaseException as e:
            with self.lock:
                self.hostResults[name] = False

    def tryHostWrapper(self, hostList, sourceEvent):
        self.hostResults = dict()
        running = True
        i = 0
        t = []

        # Spawn threads for scanning
        self.sf.info("Spawning threads to check hosts: " + str(hostList))
        for name in hostList:
            tn = 'thread_sfp_dnsbrute_' + str(random.SystemRandom().randint(1, 999999999))
            t.append(threading.Thread(name=tn, target=self.tryHost, args=(name,)))
            t[i].start()
            i += 1

        # Block until all threads are finished
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("thread_sfp_dnsbrute_"):
                    found = True

            if not found:
                running = False

            time.sleep(0.05)

        for res in self.hostResults:
            if self.hostResults.get(res, False):
                self.sendEvent(sourceEvent, res)

    # Store the result internally and notify listening modules
    def sendEvent(self, source, result):
        self.sf.info("Found a brute-forced host: " + result)
        # Report the host
        evt = SpiderFootEvent("INTERNET_NAME", result, self.__name__, source)
        self.notifyListeners(evt)

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        eventDataHash = self.sf.hashstring(eventData)
        parentEvent = event

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if srcModuleName == "sfp_dnsbrute":
            return None

        if eventDataHash in self.events:
            return None
        self.events[eventDataHash] = True

        if eventName == "INTERNET_NAME" and not self.getTarget().matches(eventData, includeChildren=False):
            if not self.opts['numbersuffix']:
                return None

            if self.checkForStop():
                return None

            h, dom = eventData.split(".", 1)

            # Try resolving common names
            wildcard = self.sf.checkDnsWildcard(dom)
            if self.opts['skipcommonwildcard'] and wildcard:
                self.sf.debug("Wildcard DNS detected on " + dom + " so skipping host iteration.")
                return None

            dom = "." + dom
            nextsubs = dict()
            for i in range(10):
                nextsubs[h + str(i) + dom] = True
                nextsubs[h + "0" + str(i) + dom] = True
                nextsubs[h + "00" + str(i) + dom] = True
                nextsubs[h + "-" + str(i) + dom] = True
                nextsubs[h + "-0" + str(i) + dom] = True
                nextsubs[h + "-00" + str(i) + dom] = True

            self.tryHostWrapper(list(nextsubs.keys()), event)

            # The rest of the module is for handling targets only
            return None

        # Only for the target, from this point forward...
        if not self.getTarget().matches(eventData, includeChildren=False):
            return None

        # Try resolving common names
        self.sf.debug("Iterating through possible sub-domains.")
        wildcard = self.sf.checkDnsWildcard(eventData)
        if self.opts['skipcommonwildcard'] and wildcard:
            self.sf.debug("Wildcard DNS detected.")
            return None

        targetList = list()
        for sub in self.sublist:
            if self.checkForStop():
                return None

            name = sub + "." + eventData

            if len(targetList) <= self.opts['_maxthreads']:
                targetList.append(name)
            else:
                self.tryHostWrapper(targetList, event)
                targetList = list()

        # Scan whatever may be left over.
        if len(targetList) > 0:
            self.tryHostWrapper(targetList, event)

        if self.opts['numbersuffix'] and not self.opts['numbersuffixlimit']:
            nextsubs = dict()
            dom = "." + eventData
            for s in self.sublist:
                if self.checkForStop():
                    return None

                for i in range(10):
                    nextsubs[s + str(i) + dom] = True
                    nextsubs[s + "0" + str(i) + dom] = True
                    nextsubs[s + "00" + str(i) + dom] = True
                    nextsubs[s + "-" + str(i) + dom] = True
                    nextsubs[s + "-0" + str(i) + dom] = True
                    nextsubs[s + "-00" + str(i) + dom] = True

                if len(list(nextsubs.keys())) >= self.opts['_maxthreads']:
                    self.tryHostWrapper(list(nextsubs.keys()), event)
                    nextsubs = dict()

            # Scan whatever may be left over.
            if len(nextsubs) > 0:
                self.tryHostWrapper(list(nextsubs.keys()), event)


# End of sfp_dnsbrute class
