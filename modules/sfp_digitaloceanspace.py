# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_digitaloceanspace
# Purpose:      SpiderFoot plug-in for identifying potential Digital Ocean spaces
#               related to the target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     16/06/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import threading
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_digitaloceanspace(SpiderFootPlugin):
    """Digital Ocean Space Finder:Footprint,Passive:Crawling and Scanning::Search for potential Digital Ocean Spaces associated with the target and attempt to list their contents."""


    # Default options
    opts = {
        "endpoints": "nyc3.digitaloceanspaces.com,sgp1.digitaloceanspaces.com,ams3.digitaloceanspaces.com",
        "suffixes": "test,dev,web,beta,bucket,space,files,content,data,prod,staging,production,stage,app,media,development,-test,-dev,-web,-beta,-bucket,-space,-files,-content,-data,-prod,-staging,-production,-stage,-app,-media,-development",
        "_maxthreads": 20
    }

    # Option descriptions
    optdescs = {
        "endpoints": "Different Digital Ocean locations to check where spaces may exist.",
        "suffixes": "List of suffixes to append to domains tried as space names"
    }

    results = None
    s3results = None
    lock = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.s3results = dict()
        self.results = dict()
        self.lock = threading.Lock()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "LINKED_URL_EXTERNAL"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["CLOUD_STORAGE_BUCKET", "CLOUD_STORAGE_BUCKET_OPEN"]

    def checkSite(self, url):
        res = self.sf.fetchUrl(url, timeout=10, useragent="SpiderFoot", noLog=True)

        if res['code'] not in [ "301", "302", "200" ] and \
            (res['content'] is None or "NoSuchBucket" in res['content']):
            self.sf.debug("Not a valid bucket: " + url)
        else:
            with self.lock:
                if "ListBucketResult" in res['content']:
                    self.s3results[url] = res['content'].count("<Key>")
                else:
                    self.s3results[url] = 0

    def threadSites(self, siteList):
        ret = list()
        self.s3results = dict()
        running = True
        i = 0
        t = []

        for site in siteList:
            if self.checkForStop():
                return None

            self.sf.info("Spawning thread to check bucket: " + site)
            t.append(threading.Thread(name='sfp_digitaloceanspaces_' + site,
                                      target=self.checkSite, args=(site,)))
            t[i].start()
            i += 1

        # Block until all threads are finished
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("sfp_digitaloceanspaces_"):
                    found = True

            if not found:
                running = False

            time.sleep(0.25)

        # Return once the scanning has completed
        return self.s3results

    def batchSites(self, sites):
        i = 0
        res = list()
        siteList = list()

        for site in sites:
            if i >= self.opts['_maxthreads']:
                data = self.threadSites(siteList)
                if data == None:
                    return res

                for ret in data.keys():
                    if data[ret]:
                        # bucket:filecount
                        res.append(ret + ":" + str(data[ret]))
                i = 0
                siteList = list()

            siteList.append(site)
            i += 1

        return res

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventName == "LINKED_URL_EXTERNAL":
            if ".digitaloceanspaces.com" in eventData:
                b = self.sf.urlFQDN(eventData)
                evt = SpiderFootEvent("CLOUD_STORAGE_BUCKET", b, self.__name__, event)
                self.notifyListeners(evt)
            return None

        targets = [ eventData.replace('.', ''), self.sf.domainKeyword(eventData, self.opts['_internettlds']) ]
        urls = list()
        for t in targets:
            for e in self.opts['endpoints'].split(','):
                suffixes = [''] + self.opts['suffixes'].split(',')
                for s in suffixes:
                    if self.checkForStop():
                        return None

                    b = t + s + "." + e
                    url = "https://" + b
                    urls.append(url)

        # Batch the scans
        ret = self.batchSites(urls)
        for b in ret:
            bucket = b.split(":")
            evt = SpiderFootEvent("CLOUD_STORAGE_BUCKET", bucket[0] + ":" + bucket[1], self.__name__, event)
            self.notifyListeners(evt)
            if bucket[2] != "0":
                evt = SpiderFootEvent("CLOUD_STORAGE_BUCKET_OPEN", bucket[0] + ":" + bucket[1] + ": " + bucket[2] + " files found.", 
                                      self.__name__, evt)
                self.notifyListeners(evt)


# End of sfp_digitaloceanspace class
