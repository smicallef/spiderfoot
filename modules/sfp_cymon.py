# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_cymon
# Purpose:      Query cymon.io using their API
#
# Author:      Steve Micallef
#
# Created:     01/02/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import base64
from datetime import datetime
import time
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_cymon(SpiderFootPlugin):
    """Cymon:Investigate,Passive:Reputation Systems:apikey:Obtain information from Cymon.io"""


    # Default options
    opts = {
        "cymon_api_key": "",
        "age_limit_days": 30,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
    }

    # Option descriptions
    optdescs = {
        "cymon_api_key": "Your Cymon.io API Key",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = dict()
    errorState = False

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
                "CO_HOSTED_SITE", "NETBLOCK_OWNER", "NETBLOCK_MEMBER",
                "AFFILIATE_INTERNET_NAME"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_INTERNET_NAME",
                "MALICIOUS_COHOST", "MALICIOUS_AFFILIATE_INTERNET_NAME",
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_NETBLOCK",
                "CO_HOSTED_SITE"]

    def query(self, qry, querytype):
        ret = None

        if self.errorState:
            return None

        if querytype == "ipblacklist":
            querytype = "ip/{0}"
        if querytype == "passive":
            querytype = "ip/{0}/domains"
        if querytype == "domblacklist":
            querytype = "domain/{0}"
        
        cymon_url = "https://cymon.io/api/nexus/v1/"
        headers = {
            'Authorization': "Token " + self.opts['cymon_api_key']
        }
        url = cymon_url + "/" + querytype.format(qry)
        res = self.sf.fetchUrl(url , timeout=self.opts['_fetchtimeout'], 
                               useragent="SpiderFoot", headers=headers)

        if res['code'] in [ "400", "429", "500", "403" ]:
            self.sf.error("Cymon.io API key seems to have been rejected or you have exceeded usage limits for the month.", False)
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.info("No Cymon.io info found for " + qry)
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from Cymon.io.", False)
            return None

        return info


    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['cymon_api_key'] == "":
            self.sf.error("You enabled sfp_cymon but did not set an API key!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None
        else:
            self.results[eventData] = True

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return None
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                    self.sf.debug("Network size bigger than permitted: " +
                                  str(IPNetwork(eventData).prefixlen) + " > " +
                                  str(self.opts['maxnetblock']))
                    return None

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return None
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxsubnet']:
                    self.sf.debug("Network size bigger than permitted: " +
                                  str(IPNetwork(eventData).prefixlen) + " > " +
                                  str(self.opts['maxsubnet']))
                    return None

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        # For IP Addresses, do the additional passive DNS lookup
        if eventName == "IP_ADDRESS":
            evtType = "CO_HOSTED_SITE"
            ret = self.query(eventData, "passive")
            if ret is None:
                self.sf.info("No Passive DNS info for " + eventData)
            elif "results" in ret:
                self.sf.debug("Found passive DNS results in Cymon.io")
                res = ret["results"]
                for rec in res:
                    last = rec.get("updated", "")
                    last_dt = datetime.strptime(last, '%Y-%m-%dT%H:%M:%SZ')
                    last_ts = int(time.mktime(last_dt.timetuple()))
                    age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                    host = rec['name']
                    if self.opts['age_limit_days'] > 0 and last_ts < age_limit_ts:
                        self.sf.debug("Record found but too old, skipping.")
                        continue
                    else:
                        e = SpiderFootEvent(evtType, host, self.__name__, event)
                        self.notifyListeners(e)

        for addr in qrylist:
            if self.checkForStop():
                return None

            if eventName == 'IP_ADDRESS' or eventName.startswith('NETBLOCK_'):
                evtType = 'MALICIOUS_IPADDR'
            if eventName == "AFFILIATE_IPADDR":
                evtType = 'MALICIOUS_AFFILIATE_IPADDR'
            if eventName == "INTERNET_NAME":
                evtType = "MALICIOUS_INTERNET_NAME"
            if eventName == 'AFFILIATE_INTERNET_NAME':
                evtType = 'MALICIOUS_AFFILIATE_INTERNET_NAME'
            if eventName == 'CO_HOSTED_SITE':
                evtType = 'MALICIOUS_COHOST'

            if eventName in [ "IP_ADDRESS", "AFFILIATE_IPADDR", "NETLBLOCK_OWNER", "NETBLOCK_MEMBER"]:
                qtype = "ipblacklist"
            else:
                qtype = "domblacklist"

            rec = self.query(addr, qtype)
            if rec is not None:
                rec_history = rec.get("sources", list())
                if len(rec_history) > 0:
                    self.sf.debug("Found malicious data results in Cymon.io")
                    created_dt = datetime.strptime(rec.get('updated'), '%Y-%m-%dT%H:%M:%SZ')
                    created_ts = int(time.mktime(created_dt.timetuple()))
                    age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                    if self.opts['age_limit_days'] > 0 and created_ts < age_limit_ts:
                        self.sf.debug("Record found but too old, skipping.")
                        continue
                    entry = "Cymon.io: " + ",".join(rec_history)
                    e = SpiderFootEvent(evtType, entry, self.__name__, event)
                    self.notifyListeners(e)
    
# End of sfp_cymon class
