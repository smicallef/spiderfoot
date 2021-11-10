# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_s3bucket
# Purpose:      SpiderFoot plug-in for identifying potential S3 buckets related to
#               the target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     24/07/2016
# Copyright:   (c) Steve Micallef 2016
# Licence:     GPL
# -------------------------------------------------------------------------------

import random
import threading
import time

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_s3bucket(SpiderFootPlugin):

    meta = {
        'name': "Amazon S3 Bucket Finder",
        'summary': "Search for potential Amazon S3 buckets associated with the target and attempt to list their contents.",
        'flags': [],
        'useCases': ["Footprint", "Passive"],
        'categories': ["Crawling and Scanning"],
        'dataSource': {
            'website': "https://aws.amazon.com/s3/",
            'model': "FREE_NOAUTH_UNLIMITED",
        }
    }

    # Default options
    opts = {
        "endpoints": "s3.amazonaws.com,s3-external-1.amazonaws.com,s3-us-west-1.amazonaws.com,s3-us-west-2.amazonaws.com,s3.ap-south-1.amazonaws.com,s3-ap-south-1.amazonaws.com,s3.ap-northeast-2.amazonaws.com,s3-ap-northeast-2.amazonaws.com,s3-ap-southeast-1.amazonaws.com,s3-ap-southeast-2.amazonaws.com,s3-ap-northeast-1.amazonaws.com,s3.eu-central-1.amazonaws.com,s3-eu-central-1.amazonaws.com,s3-eu-west-1.amazonaws.com,s3-sa-east-1.amazonaws.com",
        "suffixes": "test,dev,web,beta,bucket,space,files,content,data,prod,staging,production,stage,app,media,development,-test,-dev,-web,-beta,-bucket,-space,-files,-content,-data,-prod,-staging,-production,-stage,-app,-media,-development",
        "_maxthreads": 20
    }

    # Option descriptions
    optdescs = {
        "endpoints": "Different S3 endpoints to check where buckets may exist, as per http://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region",
        "suffixes": "List of suffixes to append to domains tried as bucket names",
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
                return False

            self.info("Spawning thread to check bucket: " + site)
            tname = str(random.SystemRandom().randint(0, 999999999))
            t.append(threading.Thread(name='thread_sfp_s3buckets_' + tname,
                                      target=self.checkSite, args=(site,)))
            t[i].start()
            i += 1

        # Block until all threads are finished
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("thread_sfp_s3buckets_"):
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
                        res.append(f"{ret}:{data[ret]}")
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
            if ".amazonaws.com" in eventData:
                b = self.sf.urlFQDN(eventData)
                if b in self.opts['endpoints']:
                    try:
                        b += "/" + eventData.split(b + "/")[1].split("/")[0]
                    except Exception:
                        # Not a proper bucket path
                        return
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
                bucketname = bucket[1].replace("//", "")
                evt = SpiderFootEvent("CLOUD_STORAGE_BUCKET_OPEN", bucketname + ": " + bucket[2] + " files found.",
                                      self.__name__, evt)
                self.notifyListeners(evt)


# End of sfp_s3bucket class
