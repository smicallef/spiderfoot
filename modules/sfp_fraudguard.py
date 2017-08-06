# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_fraudguard
# Purpose:      Query fraudguard.io using their API
#
# Author:      Steve Micallef
#
# Created:     18/06/2017
# Copyright:   (c) Steve Micallef 2017
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import base64
from datetime import datetime
import time
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_fraudguard(SpiderFootPlugin):
    """Fraudguard:Investigate,Passive:Reputation Systems:apikey:Obtain threat information from Fraudguard.io"""


    # Default options
    opts = {
        "fraudguard_api_key_account": "",
        "fraudguard_api_key_password": "",
        "age_limit_days": 90,
        'netblocklookup': True,
        'maxnetblock': 24
    }

    # Option descriptions
    optdescs = {
        "fraudguard_api_key_account": "Your Fraudguard.io API username",
        "fraudguard_api_key_password": "Your Fraudguard.io API password",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
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
        return ["IP_ADDRESS", "NETBLOCK_OWNER"]

    # What events this module produces
    def producedEvents(self):
        return [ "GEOINFO", "MALICIOUS_IPADDR", "MALICIOUS_NETBLOCK" ]

    def query(self, qry):
        fraudguard_url = "https://api.fraudguard.io/ip/" + qry
        headers = {
            'Authorization': "Basic " + base64.b64encode(self.opts['fraudguard_api_key_account'] + ":" + self.opts['fraudguard_api_key_password'])
        }

        res = self.sf.fetchUrl(fraudguard_url , timeout=self.opts['_fetchtimeout'], 
                               useragent="SpiderFoot", headers=headers)

        if res['code'] in [ "400", "429", "500", "403" ]:
            self.sf.error("Fraudguard.io API key seems to have been rejected or you have exceeded usage limits for the month.", False)
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.info("No Fraudguard.io info found for " + qry)
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from Fraudguard.io.", False)
            return None

        #print str(info)
        return info


    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['fraudguard_api_key_account'] == "" or self.opts['fraudguard_api_key_password'] == "":
            self.sf.error("You enabled sfp_fraudguard but did not set an API username/password!", False)
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

        qrylist = list()
        rtype = ""
        if eventName.startswith("NETBLOCK_"):
            rtype = "NETBLOCK"
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            rtype = "IPADDR"
            qrylist.append(eventData)

        for addr in qrylist:
            if self.checkForStop():
                return None

            rec = self.query(addr)
            if rec is not None:
                self.sf.debug("Found results in Fraudguard.io")
                # 2016-12-24T07:25:35+00:00'
                created_dt = datetime.strptime(rec.get('discover_date'), '%Y-%m-%d %H:%M:%S')
                created_ts = int(time.mktime(created_dt.timetuple()))
                age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                if self.opts['age_limit_days'] > 0 and created_ts < age_limit_ts:
                    self.sf.debug("Record found but too old, skipping.")
                    continue
                if "unknown" not in [rec['country'], rec['state'], rec['city']]:
                    dat = rec['country'] + ", " + rec['state'] + ", " + rec['city']
                    e = SpiderFootEvent("GEOINFO", dat, self.__name__, event)
                    self.notifyListeners(e)

                if rec.get('threat') != "unknown":
                    dat = rec['threat'] + " (risk level: " + rec['risk_level'] + ")"
                    e = SpiderFootEvent("MALICIOUS_" + rtype, dat, self.__name__, event)
                    self.notifyListeners(e)
    
# End of sfp_fraudguard class
