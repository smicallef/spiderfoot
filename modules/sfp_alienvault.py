# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_alienvault
# Purpose:      Query AlienVault OTX
#
# Author:      Steve Micallef
#
# Created:     26/03/2017
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from datetime import datetime
import time
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_alienvault(SpiderFootPlugin):
    """AlienVault OTX:Investigate,Passive:Reputation Systems:apikey:Obtain information from AlienVault Open Threat Exchange (OTX)"""


    # Default options
    opts = {
        "api_key": "",
        "age_limit_days": 30,
        "threat_score_min": 2,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24,
        'checkaffiliates': True
    }

    # Option descriptions
    optdescs = {
        "api_key": "AlienVault OTX API Key.",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
        "threat_score_min": "Minimum AlienVault threat score.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'checkaffiliates': "Apply checks to affiliates?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", 
                "NETBLOCK_OWNER", "NETBLOCK_MEMBER"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_NETBLOCK" ]

    def query(self, qry, querytype):
        ret = None
        targettype = "hostname"

        if ":" in qry:
            targettype = "IPv6"

        if self.sf.validIP(qry):
            targettype = "IPv4"

        if querytype not in ["passive_dns", "reputation"]:
            querytype = "reputation"

        url = "https://otx.alienvault.com:443/api/v1/indicators/" + targettype + \
              "/" + qry + "/" + querytype
        headers = {
            'Accept': 'application/json',
            'X-OTX-API-KEY': self.opts['api_key']
        }
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
                               useragent="SpiderFoot", headers=headers)

        if res['code'] == "403":
            self.sf.error("AlienVault OTX API key seems to have been rejected or you have exceeded usage limits for the month.", False)
            self.errorState = True
            return None

        if res['content'] is None or res['code'] == "404":
            self.sf.info("No AlienVault OTX info found for " + qry)
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from AlienVault OTX.", False)
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

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_alienvault but did not set an API key/password!", False)
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

        if eventName == 'AFFILIATE_IPADDR' and not self.opts.get('checkaffiliates', False):
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
            ret = self.query(eventData, "passve_dns")
            if ret is None:
                self.sf.info("No Passive DNS info for " + eventData)
            elif "passve_dns" in ret:
                self.sf.debug("Found passive DNS results in AlienVault OTX")
                res = ret["passive_dns"]
                for rec in res:
                    if "hostname" in rec:
                        host = rec['hostname']
                        try:
                            last = rec.get("last", "")
                            last_dt = datetime.strptime(last, '%Y-%m-%d %H:%M:%S')
                            last_ts = int(time.mktime(last_dt.timetuple()))
                            age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                            if self.opts['age_limit_days'] > 0 and last_ts < age_limit_ts:
                                self.sf.debug("Record found but too old, skipping.")
                                continue
                        except BaseException as e:
                            self.sf.debug("Couldn't parse date from AlienVault so assuming it's OK.")
                        e = SpiderFootEvent(evtType, host, self.__name__, event)
                        self.notifyListeners(e)

        for addr in qrylist:
            if self.checkForStop():
                return None

            if eventName == 'IP_ADDRESS' or eventName.startswith('NETBLOCK_'):
                evtType = 'MALICIOUS_IPADDR'
            if eventName == "AFFILIATE_IPADDR":
                evtType = 'MALICIOUS_AFFILIATE_IPADDR'

            rec = self.query(addr, "reputation")
            if rec is not None:
                if rec.get("reputation", None):
                    self.sf.debug("Found reputation info in AlienVault OTX")
                    rec_history = rec['reputation'].get("activities", list())
                    if rec['reputation']['threat_score'] < self.opts['threat_score_min']:
                        continue
                    descr = "AlienVault Threat Score: " + str(rec['reputation']['threat_score']) + ":"

                    for result in rec_history:
                        nm = result.get("name", None)
                        if nm is None or nm in descr:
                            continue
                        descr += "\n - " + nm
                        created = result.get("last_date", "")
                        # 2014-11-06T10:45:00.000
                        try:
                            created_dt = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S')
                            created_ts = int(time.mktime(created_dt.timetuple()))
                            age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                            if self.opts['age_limit_days'] > 0 and created_ts < age_limit_ts:
                                self.sf.debug("Record found but too old, skipping.")
                                continue
                        except BaseException as e:
                            self.sf.debug("Couldn't parse date from AlienVault so assuming it's OK.")
                    e = SpiderFootEvent(evtType, descr, self.__name__, event)
                    self.notifyListeners(e)

# End of sfp_alienvault class
