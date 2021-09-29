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

import random
import threading
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_digitaloceanspace(SpiderFootPlugin):

    meta = {
        'name': "Digital Ocean Space Finder",
        'summary': "Search for potential Digital Ocean Spaces associated with the target and attempt to list their contents.",
        'flags': [],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://www.digitalocean.com/products/spaces/",
            'model': "FREE_NOAUTH_UNLIMITED"
        }
    }

    # Default options
    opts = {
        "endpoints": "nyc3.digitaloceanspaces.com,sgp1.digitaloceanspaces.com,ams3.digitaloceanspaces.com",
        "suffixes": "test,dev,web,beta,bucket,space,files,content,data,prod,staging,production,stage,app,media,development,-test,-dev,-web,-beta,-bucket,-space,-files,-content,-data,-prod,-staging,-production,-stage,-app,-media,-development",
        "_maxthreads": 20
    }

    # Option descriptions
    optdescs = {
        "endpoints": "Different Digital Ocean locations to check where spaces may exist.",
        "suffixes": "List of suffixes to append to domains tried as space names",
        "_maxthreads": "Maximum threads"
    }

    results = None
    s3results = dict()
    lock = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.s3results = dict()
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

        if not res['content']:
            return

        if "NoSuchBucket" in res['content']:
            self.debug(f"Not a valid bucket: {url}")
            return

        # Bucket found
        if res['code'] in ["301", "302", "200"]:
            # Bucket has files
            if "ListBucketResult" in res['content']:
                with self.lock:
                    self.s3results[url] = res['content'].count("<Key>")
            else:
                # Bucket has no files
                with self.lock:
                    self.s3results[url] = 0

    def threadSites(self, siteList):
        self.s3results = dict()
        running = True
        i = 0
        t = []

        for site in siteList:
            if self.checkForStop():
                return None

            self.info("Spawning thread to check bucket: " + site)
            tname = str(random.SystemRandom().randint(0, 999999999))
            t.append(threading.Thread(name='thread_sfp_digitaloceanspaces_' + tname,
                                      target=self.checkSite, args=(site,)))
            t[i].start()
            i += 1

        # Block until all threads are finished
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("thread_sfp_digitaloceanspaces_"):
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
                if data is None:
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
            return

        self.results[eventData] = True

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventName == "LINKED_URL_EXTERNAL":
            if ".digitaloceanspaces.com" in eventData:
                b = self.sf.urlFQDN(eventData)
                evt = SpiderFootEvent("CLOUD_STORAGE_BUCKET", b, self.__name__, event)
                self.notifyListeners(evt)
            return

        targets = [eventData.replace('.', '')]
        kw = self.sf.domainKeyword(eventData, self.opts['_internettlds'])
        if kw:
            targets.append(kw)

        urls = list()
        for t in targets:
            for e in self.opts['endpoints'].split(','):
                suffixes = [''] + self.opts['suffixes'].split(',')
                for s in suffixes:
                    if self.checkForStop():
                        return

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
