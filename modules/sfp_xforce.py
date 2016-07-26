# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_xforce
# Purpose:      Query XForce Exchange
#
# Author:      Koen Van Impe
#
# Created:     23/12/2015
# Updated:     26/07/2016, Steve Micallef - re-focused to be reputation-centric
# Copyright:   (c) Koen Van Impe
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import base64
from datetime import datetime
import time

from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_xforce(SpiderFootPlugin):
    """XForce Exchange:Investigate,Passive:Obtain information from IBM X-Force Exchange"""

    # Default options
    opts = {
        "xforce_api_key": "",
        "xforce_password": "",
        "age_limit_days": 30
    }

    # Option descriptions
    optdescs = {
        "xforce_api_key": "The X-Force Exchange API Key",
        "xforce_password": "The X-Force Exchange API Password",
        "age_limit_days": "Ignore any records older than this many days"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "INTERNET_NAME",
                "AFFILIATE_DOMAIN", "CO_HOSTED_SITE", "NETBLOCK_OWNER",
                "NETBLOCK_MEMBER"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME",
                "MALICIOUS_COHOST", "MALICIOUS_AFFILIATE_INTERNET_NAME",
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_NETBLOCK",
                "MALICIOUS_SUBNET",
                "DNS_PASSIVE"]

    def query(self, qry, querytype):
        ret = None

        if querytype not in ["ipr/malware", "ipr/history"]:
            querytype = "ipr/malware"

        xforce_url = "https://api.xforce.ibmcloud.com"
        headers = {
            'Accept': 'application/json',
            'Authorization': "Basic " + base64.b64encode(self.opts['xforce_api_key'] + ":" + self.opts['xforce_password'])
        }
        url = xforce_url + "/" + querytype + "/" + qry
        res = self.sf.fetchUrl(url , timeout=self.opts['_fetchtimeout'], useragent="SpiderFoot", headers=headers)

        if res['content'] is None:
            self.sf.info("No XForce info found for " + qry)
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from XForce.", False)
            return None

        return info


    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        infield_sep = " ; "

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        for addr in qrylist:
            if self.checkForStop():
                return None

            if eventName == 'IP_ADDRESS':
                evtType = 'MALICIOUS_IPADDR'
            if eventName == "AFFILIATE_IPADDR":
                evtType = 'MALICIOUS_AFFILIATE_IPADDR'
            if eventName == "INTERNET_NAME":
                evtType = "MALICIOUS_INTERNET_NAME"
            if eventName == 'AFFILIATE_INTERNET_NAME':
                evtType = 'MALICIOUS_AFFILIATE_INTERNET_NAME'
            if eventName == 'CO_HOSTED_SITE':
                evtType = 'MALICIOUS_COHOST'

            rec = self.query(addr, "ipr/history")
            if rec is not None:
                rec_history = rec.get("history", None)
                if rec_history is not None:
                    self.sf.info("Found history results in XForce")
                    for result in rec_history:
                        reasonDescription = result.get("reasonDescription", "")
                        created = result.get("created", "")
                        # 2014-11-06T10:45:00.000Z
                        created_dt = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000Z')
                        created_ts = int(time.mktime(created_dt.timetuple()))
                        age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                        if created_ts < age_limit_ts:
                            self.sf.info("Record found but too old, skipping.")
                            continue
                        reason = result.get("reason", "")
                        score = result.get("score", 0)
                        cats = result.get("cats", None)
                        cats_description = ""
                        if int(score) < 2:
                            self.sf.info("Non-malicious results, skipping.")
                            continue
                        if cats is not None:
                            for cat in cats:
                                cats_description = cats_description + cat + " "
                        entry = reason + infield_sep + \
                                    str(score) + infield_sep + \
                                    created  + infield_sep + \
                                    cats_description
                        e = SpiderFootEvent(evtType, entry, self.__name__, event)
                        self.notifyListeners(e)
                
            rec = self.query(addr, "ipr/malware")
            if rec is not None:
                rec_malware = rec.get("malware", None)
                if rec_malware is not None:
                    self.sf.info("Found malware results in XForce")
                    for result in rec_malware:
                        count = result.get("count", "")
                        origin = result.get("origin", "")
                        domain = result.get("domain", "")
                        uri = result.get("uri", "")
                        md5 = result.get("md5", "")
                        lastseen = result.get("last", "")
                        firstseen = result.get("first", "")
                        family = result.get("family", None)
                        family_description = ""
                        if family is not None:
                            for f in family:
                                family_description = family_description + f + " "
                        entry = origin + infield_sep + \
                                    family_description + infield_sep + \
                                    md5 + infield_sep + \
                                    domain + infield_sep + \
                                    uri + infield_sep + \
                                    firstseen + infield_sep + \
                                    lastseen
                        e = SpiderFootEvent(evtType, entry, self.__name__, event)
                        self.notifyListeners(e)

# End of sfp_xforce class
