# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_greynoise
# Purpose:      Query Greynoise's API
#
# Author:      Steve Micallef
#
# Created:     20/11/2018
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from datetime import datetime
import time
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_greynoise(SpiderFootPlugin):
    """Greynoise:Investigate,Passive:Reputation Systems:apikey:Obtain information from Greynoise.io's Enterprise API."""


    # Default options
    opts = {
        "api_key": "",
        "age_limit_days": 30,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
        #'asnlookup': True
    }

    # Option descriptions
    optdescs = {
        "api_key": "Greynoise API Key.",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
        #'asnlookup': "Look up ASNs that your target is a member of?"
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
                "NETBLOCK_MEMBER", "NETBLOCK_OWNER"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_ASN", "MALICIOUS_SUBNET",
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_NETBLOCK",
                "COMPANY_NAME", "GEOINFO", "BGP_AS_MEMBER", "OPERATING_SYSTEM",
                "RAW_RIR_DATA" ]

    def queryIP(self, qry):
        ret = None

        header = { "key": self.opts['api_key'] }
        url = "https://" + "enterprise.api.greynoise.io/v2/noise/context/" + qry
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
                               useragent="SpiderFoot", headers=header)

        if res['code'] not in [ "200" ]:
            self.sf.error("Greynoise API key seems to have been rejected or you have exceeded usage limits.", False)
            self.errorState = True
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from Greynoise.", False)
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
            self.sf.error("You enabled sfp_greynoise but did not set an API key!", False)
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

        for addr in qrylist:
            if self.checkForStop():
                return None

            if eventName == 'IP_ADDRESS' or eventName.startswith('NETBLOCK_'):
                evtType = 'MALICIOUS_IPADDR'
            if eventName == "AFFILIATE_IPADDR":
                evtType = 'MALICIOUS_AFFILIATE_IPADDR'

            rec = self.queryIP(addr)
            if rec is not None:
                if rec.get("seen", None):
                    self.sf.debug("Found threat info in Greynoise")
                    lastseen = rec.get("last_seen", "1970-01-01")
                    lastseen_dt = datetime.strptime(lastseen, '%Y-%m-%d')
                    lastseen_ts = int(time.mktime(lastseen_dt.timetuple()))
                    age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                    if self.opts['age_limit_days'] > 0 and lastseen_ts < age_limit_ts:
                        self.sf.debug("Record found but too old, skipping.")
                        continue

                    # Only report meta data about the target, not affiliates
                    if rec.get("metadata") and eventName == "IP_ADDRESS":
                        met = rec.get("metadata")
                        if met.get("country", "unknown") != "unknown":
                            loc = ""
                            if met.get("city"):
                                loc = met.get("city") + ", "
                            loc += met.get("country")
                            e = SpiderFootEvent("GEOINFO", loc, self.__name__, event)
                            self.notifyListeners(e)
                        if met.get("asn", "unknown") != "unknown":
                            asn = met.get("asn").replace("AS", "")
                            e = SpiderFootEvent("BGP_AS_MEMBER", asn, self.__name__, event)
                            self.notifyListeners(e)
                        if met.get("organization", "unknown") != "unknown":
                            e = SpiderFootEvent("COMPANY_NAME", met.get("organization"), self.__name__, event)
                            self.notifyListeners(e)
                        if met.get("os", "unknown") != "unknown":
                            e = SpiderFootEvent("OPERATING_SYSTEM", met.get("os"), self.__name__, event)
                            self.notifyListeners(e)
                        e = SpiderFootEvent("RAW_RIR_DATA", str(rec), self.__name__, event)
                        self.notifyListeners(e)

                    if rec.get("classification"):
                        descr = "Greynoise [" + addr + "]\n - Classification: " + rec.get("classification")
                        if rec.get("tags"):
                            descr += ", Tags: " + ", ".join(rec.get("tags"))
                        else:
                            descr += "\n - " + "Raw data: " + str(rec.get("raw_data"))
                        descr += "\n<SFURL>https://viz.greynoise.io/ip/" + addr + "</SFURL>"
                        e = SpiderFootEvent(evtType, descr, self.__name__, event)
                        self.notifyListeners(e)

# End of sfp_greynoise class
