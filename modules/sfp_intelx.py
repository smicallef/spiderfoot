# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_intelx
# Purpose:      Query IntelligenceX (intelx.io) for identified IP addresses,
#               domains, e-mail addresses and phone numbers.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     28/04/2019
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import datetime
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_intelx(SpiderFootPlugin):
    """IntelligenceX:Investigate,Passive:Search Engines:apikey:Obtain information from IntelligenceX about identified IP addresses, domains, e-mail addresses and phone numbers."""

    # Default options
    opts = {
        "api_key": "9df61df0-84f7-4dc7-b34c-8ccfb8646ace",
        "base_url": "public.intelx.io",
        "checkcohosts": False,
        "checkaffiliates": False,
        'netblocklookup': False,
        'maxnetblock': 24,
        'subnetlookup': False,
        'maxsubnet': 24,
        'maxage': 90
    }

    # Option descriptions
    optdescs = {
        "api_key": "IntelligenceX API key.",
        "base_url": "API URL, as provided in your IntelligenceX account settings.",
        "checkcohosts": "Check co-hosted sites?",
        "checkaffiliates": "Check affiliates?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxage': "Maximum age (in days) of results to be considered valid."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "INTERNET_NAME", "EMAILADDR",
                "CO_HOSTED_SITE", "PHONE_NUMBER", "BITCOIN_ADDRESS"]

    # What events this module produces
    def producedEvents(self):
        return ["LEAKSITE_URL", "DARKNET_MENTION_URL", 
                "INTERNET_NAME", "DOMAIN_NAME",
                "EMAILADDR", "EMAILADDR_GENERIC"]

    def query(self, qry, qtype):
        retdata = list()

        headers = {
            "User-Agent": "SpiderFoot",
            "x-key": self.opts['api_key'],
        }

        payload = {
            "term": qry,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": 100,
            "timeout": 0,
            "datefrom": "",
            "dateto": "",
            "sort": 4,
            "media": 0,
            "terminate": []
        } 

        url = 'https://' + self.opts['base_url']  + '/' + qtype + '/search'
        res = self.sf.fetchUrl(url, postData=json.dumps(payload), 
                               headers=headers, timeout=self.opts['_fetchtimeout'])

        if res['content'] is None:
            self.sf.info("No IntelligenceX info found for " + qry)
            return None

        try:
            ret = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from IntelligenceX: " + str(e), False)
            self.errorState = True
            return None

        if ret.get('status', -1) == 0:
            #Craft API URL with the id to return results
            resulturl = url + "/result?id=%s" % str(ret['id'])
            limit = 30
            count = 0
            status = 3  # status 3 = No results yet, keep trying. 0 = Success with results
            while status in [3, 0] and count < limit:
                if self.checkForStop():
                    return None

                res = self.sf.fetchUrl(resulturl, headers=headers)
                if res['content'] is None:
                    self.sf.info("No IntelligenceX info found for results from " + qry)
                    return None

                try:
                    ret = json.loads(res['content'])
                except Exception as e:
                    self.sf.error("Error processing JSON response from IntelligenceX: " + str(e), False)
                    return None

                status = ret['status']
                count += 1

                retdata.append(ret)
                # No more results left
                if status == 1:
                    #print data in json format to manipulate as desired
                    break

                time.sleep(1)
                
        return retdata

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        if self.opts['api_key'] == "" or self.opts['base_url'] == "":
            self.sf.error("You enabled sfp_intelx but did not set an API key and/or base URL!", False)
            self.errorState = True
            return None

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
            return None

        if eventName == 'CO_HOSTED_SITE' and not self.opts['checkcohosts']:
            return None

        data = self.query(eventData, "intelligent")
        if data is None:
            return None

        self.sf.info("Found IntelligenceX leak data for " + eventData)
        agelimit = int(time.time() * 1000) - (86400000 * self.opts['maxage'])
        for info in data:
            for rec in info.get("records", dict()):
                try:
                    last_seen = int(datetime.datetime.strptime(rec['added'].split(".")[0], '%Y-%m-%dT%H:%M:%S').strftime('%s')) * 1000
                    if last_seen < agelimit:
                        self.sf.debug("Record found but too old, skipping.")
                        continue

                    val = None
                    evt = None
                    if rec['bucket'] == "pastes":
                        evt = "LEAKSITE_URL"
                        val = rec['keyvalues'][0]['value']
                    if rec['bucket'].startswith("darknet."):
                        evt = "DARKNET_MENTION_URL"
                        val = rec['name']

                    if not val or not evt:
                        self.sf.debug("Unexpected record, skipping (" + str(rec['bucket'] + ")"))
                        continue
                except BaseException as e:
                    self.sf.error("Error processing content from IntelX: " + str(e), False)
                    continue
                    
                # Notify other modules of what you've found
                e = SpiderFootEvent(evt, val, self.__name__, event)
                self.notifyListeners(e)

        if "public.intelx.io" in self.opts['base_url'] or eventName != "INTERNET_NAME":
            return None

        data = self.query(eventData, "phonebook")
        if data is None:
            return None

        self.sf.info("Found IntelligenceX host and email data for " + eventData)
        for info in data:
            for rec in info.get("selectors", dict()):
                try:
                    val = rec['selectorvalueh']
                    evt = None
                    if rec['selectortype'] == 1: #Email
                        evt = "EMAILADDR"
                        if val.split("@")[0] in self.opts['_genericusers'].split(","):
                            evt = "EMAILADDR_GENERIC"
                    if rec['selectortype'] == 2: #Domain
                        evt = "INTERNET_NAME"
                        if val == eventData:
                            continue
                    if rec['selectortype'] == 3: #URL
                        evt = "LINKED_URL_INTERNAL"

                    if not val or not evt:
                        self.sf.debug("Unexpected record, skipping.")
                        continue
                except BaseException as e:
                    self.sf.error("Error processing content from IntelX: " + str(e), False)
                    continue

                # Notify other modules of what you've found
                e = SpiderFootEvent(evt, val, self.__name__, event)
                self.notifyListeners(e)

                if evt == "INTERNET_NAME" and self.sf.isDomain(val, self.opts['_internettlds']):
                    e = SpiderFootEvent("DOMAIN_NAME", val, self.__name__, event)
                    self.notifyListeners(e)
            



# End of sfp_intelx class
