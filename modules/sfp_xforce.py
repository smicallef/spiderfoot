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
    """XForce Exchange:Investigate,Passive:Reputation Systems:apikey:Obtain information from IBM X-Force Exchange"""

    # Default options
    opts = {
        "xforce_api_key": "",
        "xforce_api_key_password": "",
        "age_limit_days": 30,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24,
        'maxcohost': 100,
        'checkaffiliates': True
    }

    # Option descriptions
    optdescs = {
        "xforce_api_key": "X-Force Exchange API Key.",
        "xforce_api_key_password": "X-Force Exchange API Password.",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        'checkaffiliates': "Apply checks to affiliates?"
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0

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

        if querytype not in ["ipr/malware", "ipr/history", "resolve"]:
            querytype = "ipr/malware"

        xforce_url = "https://api.xforce.ibmcloud.com"
        headers = {
            'Accept': 'application/json',
            'Authorization': "Basic " + base64.b64encode(self.opts['xforce_api_key'] + ":" + self.opts['xforce_api_key_password'])
        }
        url = xforce_url + "/" + querytype + "/" + qry
        res = self.sf.fetchUrl(url , timeout=self.opts['_fetchtimeout'], useragent="SpiderFoot", headers=headers)

        if res['code'] in [ "400", "401", "402", "403" ]:
            self.sf.error("XForce API key seems to have been rejected or you have exceeded usage limits for the month.", False)
            self.errorState = True
            return None

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

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['xforce_api_key'] == "" or self.opts['xforce_api_key_password'] == "":
            self.sf.error("You enabled sfp_xforce but did not set an API key/password!", False)
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

        if eventName.startswith('AFFILIATE_') and not self.opts.get('checkaffiliates', False):
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
            if self.cohostcount > self.opts['maxcohost']:
                return None

            ret = self.query(eventData, "resolve")
            if ret is None:
                self.sf.info("No Passive DNS info for " + eventData)
            elif "Passive" in ret:
                self.sf.debug("Found passive DNS results in Xforce")
                res = ret["Passive"]['records']
                for rec in res:
                    if rec['recordType'] == "A":
                        last = rec.get("last", None)
                        if not last:
                            continue
                        last_dt = datetime.strptime(last, '%Y-%m-%dT%H:%M:%SZ')
                        last_ts = int(time.mktime(last_dt.timetuple()))
                        age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                        host = rec['value']
                        if self.opts['age_limit_days'] > 0 and last_ts < age_limit_ts:
                            self.sf.debug("Record found but too old, skipping.")
                            continue
                        else:
                            e = SpiderFootEvent(evtType, host, self.__name__, event)
                            self.notifyListeners(e)
                            self.cohostcount += 1

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

            rec = self.query(addr, "ipr/history")
            if rec is not None:
                rec_history = rec.get("history", list())
                if len(rec_history) > 0:
                    self.sf.debug("Found history results in XForce")
                    for result in rec_history:
                        reasonDescription = result.get("reasonDescription", "")
                        created = result.get("created", None)
                        # 2014-11-06T10:45:00.000Z
                        if not created:
                            continue
                        created_dt = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000Z')
                        created_ts = int(time.mktime(created_dt.timetuple()))
                        age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                        if self.opts['age_limit_days'] > 0 and created_ts < age_limit_ts:
                            self.sf.debug("Record found but too old, skipping.")
                            continue
                        reason = result.get("reason", "")
                        score = result.get("score", 0)
                        cats = result.get("cats", None)
                        cats_description = ""
                        if int(score) < 2:
                            self.sf.debug("Non-malicious results, skipping.")
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

            # ipr/malware doesn't support hostnames
            if eventName in [ "CO_HOSTED_SITE", "INTERNET_NAME", "AFFILIATE_INTERNET_NAME" ]:
                continue

            rec = self.query(addr, "ipr/malware")
            if rec is not None:
                rec_malware = rec.get("malware", list())
                if len(rec_malware) > 0:
                    self.sf.debug("Found malware results in XForce")
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

                        last = rec.get("last", None)
                        if not last:
                            continue
                        last_dt = datetime.strptime(last, '%Y-%m-%dT%H:%M:%S.000Z')
                        last_ts = int(time.mktime(last_dt.timetuple()))
                        age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                        host = rec['value']
                        if self.opts['age_limit_days'] > 0 and last_ts < age_limit_ts:
                            self.sf.debug("Record found but too old, skipping.")
                            continue
                        else:
                            e = SpiderFootEvent(evtType, entry, self.__name__, event)
                            self.notifyListeners(e)

# End of sfp_xforce class
