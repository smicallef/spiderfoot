# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_commoncrawl
# Purpose:      Searches the commoncrawl.org project's indexes for URLs related
#               to the target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     05/09/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_commoncrawl(SpiderFootPlugin):
    """CommonCrawl:Footprint:Crawling and Scanning::Searches for URLs found through CommonCrawl.org."""


    # Default options
    opts = {
        "indexes": 6
    }

    # Option descriptions
    optdescs = {
        "indexes": "Number of most recent indexes to attempt, because results tend to be occasionally patchy."
    }

    results = dict()
    indexBase = list()
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.indexBase = list()
        self.errorState = False

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    def search(self, target):
        ret = list()
        for index in self.indexBase:
            url = "https://index.commoncrawl.org/" + index + \
                  "-index?url=" + target + "/*&output=json"
            res = self.sf.fetchUrl(url , timeout=60,
                                   useragent="SpiderFoot")

            if res['code'] in [ "400", "401", "402", "403", "404" ]:
                self.sf.error("CommonCrawl search doesn't seem to be available.", False)
                self.errorState = True
                return None

            if not res['content']:
                self.sf.error("CommonCrawl search doesn't seem to be available.", False)
                self.errorState = True
                return None

            ret.append(res['content'])

        return ret
        
    def getLatestIndexes(self):
        url = "https://commoncrawl.s3.amazonaws.com/cc-index/collections/index.html"
        res = self.sf.fetchUrl(url , timeout=60, 
                               useragent="SpiderFoot")

        if res['code'] in [ "400", "401", "402", "403", "404" ]:
            self.sf.error("CommonCrawl index collection doesn't seem to be available.", False)
            self.errorState = True
            return list()

        if not res['content']:
            self.sf.error("CommonCrawl index collection doesn't seem to be available.", False)
            self.errorState = True
            return list()

        indexes = re.findall(".*(CC-MAIN-\d+-\d+).*", res['content'])
        highest = 0
        indexlist = dict()
        for m in indexes:
            ms = m.replace("CC-MAIN-", "").replace("-", "")
            indexlist[ms] = True

        topindexes = sorted(indexlist.keys(), reverse=True)[0:self.opts['indexes']]

        if len(topindexes) < self.opts['indexes']:
            self.sf.error("Not able to find latest CommonCrawl indexes.", False)
            self.errorState = True
            return list()

        retindex = list()
        for i in topindexes:
            retindex.append("CC-MAIN-" + str(i)[0:4] + "-" + str(i)[4:6])
        self.sf.debug("CommonCrawl indexes: " + str(retindex))
        return retindex

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["INTERNET_NAME"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["LINKED_URL_INTERNAL"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if eventData in self.results:
            return None
        else:
            self.results[eventData] = True

        if len(self.indexBase) == 0:
            self.indexBase = self.getLatestIndexes()

        if not self.indexBase:
            self.sf.error("Unable to fetch CommonCrawl index.", False)
            return None

        if len(self.indexBase) == 0:
            self.sf.error("Unable to fetch CommonCrawl index.", False)
            return None

        data = self.search(eventData)
        if not data:
            self.sf.error("Unable to obtain content from CommonCrawl.", False)
            return None

        for content in data:
            try:
                for line in content.split("\n"):
                    if self.checkForStop():
                        return None

                    if len(line) < 2:
                        continue
                    link = json.loads(line)
                    if 'url' not in link:
                        continue
                    evt = SpiderFootEvent("LINKED_URL_INTERNAL", link['url'],
                                          self.__name__, event)
                    self.notifyListeners(evt)
            except BaseException as e:
                self.sf.error("Malformed JSON from CommonCrawl.org: " + str(e), False)
                return None

# End of sfp_commoncrawl class
