# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_arin
# Purpose:      Queries the ARIN internet registry to get netblocks and other 
#               bits of info.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     23/02/2018
# Copyright:   (c) Steve Micallef 2018
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_arin(SpiderFootPlugin):
    """ARIN:Footprint,Investigate,Passive:Public Registries::Queries ARIN registry for contact information."""


    # Default options
    opts = {}

    results = dict()
    currentEventSrc = None
    memCache = dict()
    keywords = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.memCache = dict()
        self.currentEventSrc = None

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['DOMAIN_NAME', 'HUMAN_NAME']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["RAW_RIR_DATA"]

    # Fetch content and notify of the raw data
    def fetchRir(self, url):
        if url in self.memCache:
            res = self.memCache[url]
        else:
            head = { "Accept": "application/json" }
            res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'],
                                   useragent=self.opts['_useragent'], headers=head)
            if res['content'] is not None:
                self.memCache[url] = res
                evt = SpiderFootEvent("RAW_RIR_DATA", res['content'], self.__name__,
                                      self.currentEventSrc)
                self.notifyListeners(evt)
        return res

    # Owner information about an AS
    def query(self, qtype, value):
        ownerinfo = dict()
        url = "https://whois.arin.net/rest/"

        if qtype == "domain":
            url += "pocs;domain=@" + value

        try:
            if qtype == "name":
                fname, lname = value.split(" ", 1)
                if fname.endswith(","):
                    t = fname
                    fname = lname
                    lname = t
                url += "pocs;first=" + fname + ";last=" + lname
        except BaseException as e:
            self.sf.debug("Couldn't process name: " + value + " (" + str(e) + ")")
            return None

        if qtype == "contact":
            url = value

        res = self.fetchRir(url)
        if res['content'] is None:
            self.sf.debug("No info found/available for " + value + " at ARIN.")
            return None

        try:
            j = json.loads(res['content'])
            return j
        except Exception as e:
            self.sf.debug("Error processing JSON response.")
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if eventName == "DOMAIN_NAME":
            ret = self.query("domain", eventData)
            if not ret:
                return None
            if "pocs" in ret:
                if "pocRef" in ret['pocs']:
                    ref = list()
                    # Might be a list or a dictionary
                    if type(ret['pocs']['pocRef']) == dict:
                        ref = [ret['pocs']['pocRef']]
                    else:
                        ref = ret['pocs']['pocRef']
                    for p in ref:
                        name = p['@name']
                        if "," in name:
                            sname = name.split(", ", 1)
                            name = sname[1] + " " + sname[0]

                        # A bit of a hack. The reason we do this is because
                        # the names are separated in the content and sfp_names
                        # won't recognise it. So we submit this and see if it
                        # really is considered a name.
                        evt = SpiderFootEvent("RAW_RIR_DATA", "Possible full name: " + name, 
                                              self.__name__, self.currentEventSrc)
                        self.notifyListeners(evt)

                        # We just want the raw data so we can get potential
                        # e-mail addresses.
                        self.query("contact", p['$'])

        if eventName == "HUMAN_NAME":
            ret = self.query("name", eventData)
            if not ret:
                return None
            if "pocs" in ret:
                if "pocRef" in ret['pocs']:
                    ref = list()
                    # Might be a list or a dictionary
                    if type(ret['pocs']['pocRef']) == dict:
                        ref = [ret['pocs']['pocRef']]
                    else:
                        ref = ret['pocs']['pocRef']
                    for p in ref:
                        # We just want the raw data so we can get potential
                        # e-mail addresses.
                        self.query("contact", p['$'])
                        
# End of sfp_arin class
