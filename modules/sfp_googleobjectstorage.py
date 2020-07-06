# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_googleobjectstorage
# Purpose:      SpiderFoot plug-in for identifying potential Google Object Storage
#               buckets related to the target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     24/01/2020
# Copyright:   (c) Steve Micallef 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import threading
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_googleobjectstorage(SpiderFootPlugin):
    """Google Object Storage Finder:Footprint,Passive:Crawling and Scanning::Search for potential Google Object Storage buckets associated with the target and attempt to list their contents."""


    # Default options
    opts = {
        "suffixes": "test,dev,web,beta,bucket,space,files,content,data,prod,staging,production,stage,app,media,development,-test,-dev,-web,-beta,-bucket,-space,-files,-content,-data,-prod,-staging,-production,-stage,-app,-media,-development",
        "_maxthreads": 20
    }

    # Option descriptions
    optdescs = {
        "suffixes": "List of suffixes to append to domains tried as bucket names"
    }

    results = None
    gosresults = dict()
    lock = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.gosresults = dict()
        self.results = self.tempStorage()
        self.lock = threading.Lock()

        for opt in list(userOpts.keys()):
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
            if "ListBucketResult" in res['content']:
                with self.lock:
                    self.gosresults[url] = res['content'].count("<Key>")
            else:
                with self.lock:
                    self.gosresults[url] = 0

    def threadSites(self, siteList):
        ret = list()
        self.gosresults = dict()
        running = True
        i = 0
        t = []

        for site in siteList:
            if self.checkForStop():
                return None

            self.sf.info("Spawning thread to check bucket: " + site)
            t.append(threading.Thread(name='thread_sfp_googleobjectstorage_' + site,
                                      target=self.checkSite, args=(site,)))
            t[i].start()
            i += 1

        # Block until all threads are finished
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("thread_sfp_googleobjectstorage_"):
                    found = True

            if not found:
                running = False

            time.sleep(0.25)

        # Return once the scanning has completed
        return self.gosresults

    def batchSites(self, sites):
        i = 0
        res = list()
        siteList = list()

        for site in sites:
            if i >= self.opts['_maxthreads']:
                data = self.threadSites(siteList)
                if data == None:
                    return res

                for ret in list(data.keys()):
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

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        if eventName == "LINKED_URL_EXTERNAL":
            if ".storage.googleapis.com" in eventData:
                b = self.sf.urlFQDN(eventData)
                evt = SpiderFootEvent("CLOUD_STORAGE_BUCKET", b, self.__name__, event)
                self.notifyListeners(evt)
            return None

        targets = [ eventData.replace('.', '') ]
        kw = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
        if kw:
            targets.append(kw)

        urls = list()
        for t in targets:
            suffixes = [''] + self.opts['suffixes'].split(',')
            for s in suffixes:
                if self.checkForStop():
                    return None

                b = t + s + ".storage.googleapis.com"
                url = "https://" + b
                urls.append(url)

        # Batch the scans
        ret = self.batchSites(urls)
        for b in ret:
            bucket = b.split(":")
            evt = SpiderFootEvent("CLOUD_STORAGE_BUCKET", bucket[0] + ":" + bucket[1], self.__name__, event)
            self.notifyListeners(evt)
            if bucket[2] != "0":
                bucketname = bucket[1].replace("//", "")
                evt = SpiderFootEvent("CLOUD_STORAGE_BUCKET_OPEN", bucketname + ": " + bucket[2] + " files found.", 
                                      self.__name__, evt)
                self.notifyListeners(evt)


# End of sfp_googleobjectstorage class
