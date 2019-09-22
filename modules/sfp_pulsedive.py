# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_pulsedive
# Purpose:      Query Pulsedive's API
#
# Author:      Steve Micallef
#
# Created:     04/09/2018
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from datetime import datetime
import time
from netaddr import IPNetwork
import urllib
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_pulsedive(SpiderFootPlugin):
    """Pulsedive:Investigate,Passive:Reputation Systems:apikey:Obtain information from Pulsedive's API."""

    # Default options
    opts = {
        "api_key": "",
        # The rate limit for free users is 30 requests per minute
        "delay": 2,
        "age_limit_days": 30,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
    }

    # Option descriptions
    optdescs = {
        "api_key": "Pulsedive API Key.",
        "delay": "Delay between requests, in seconds.",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
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
        return ["IP_ADDRESS", "AFFILIATE_IPADDR", "INTERNET_NAME",
                "NETBLOCK_OWNER", "NETBLOCK_MEMBER"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_INTERNET_NAME", "MALICIOUS_IPADDR", 
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_NETBLOCK",
                'TCP_PORT_OPEN']

    # https://pulsedive.com/api/
    def query(self, qry):
        params = {
            'indicator': qry.encode('raw_unicode_escape'),
            'key': self.opts['api_key']
        }

        url = 'https://pulsedive.com/api/info.php?' + urllib.urlencode(params)
        res = self.sf.fetchUrl(url, timeout=30, useragent="SpiderFoot")

        time.sleep(self.opts['delay'])

        if res['code'] == "403":
            self.sf.error("Pulsedive API key seems to have been rejected or you have exceeded usage limits for the month.", False)
            self.errorState = True
            return None

        if res['content'] is None:
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            print(str(res['content']))
            self.sf.error("Error processing JSON response from Pulsedive.", False)
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
            self.sf.error("You enabled sfp_pulsedive but did not set an API key!", False)
            self.errorState = True
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        self.results[eventData] = True

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return None

            if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                self.sf.debug("Network size bigger than permitted: " +
                              str(IPNetwork(eventData).prefixlen) + " > " +
                              str(self.opts['maxnetblock']))
                return None

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return None

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
            if eventName == "INTERNET_NAME":
                evtType = 'MALICIOUS_INTERNET_NAME'

            rec = self.query(addr)

            if rec is None:
                continue

            attributes = rec.get('attributes')

            if attributes:
                ports = attributes.get('port')
                if ports:
                    for p in ports:
                        e = SpiderFootEvent('TCP_PORT_OPEN', addr + ':' + p, self.__name__, event)
                        self.notifyListeners(e)

            threats = rec.get('threats')

            if not threats:
                continue

            self.sf.debug("Found threat info in Pulsedive")

            for result in threats:
                descr = addr
                tid = str(rec.get("iid"))
                descr += "\n - " + result.get("name", "")
                descr += " (" + result.get("category", "") + ")"

                if tid:
                    descr += "\n<SFURL>https://pulsedive.com/indicator/?iid=" + tid + "</SFURL>"

                created = result.get("stamp_linked", "")
                # 2018-02-20 03:51:59
                try:
                    created_dt = datetime.strptime(created, '%Y-%m-%d %H:%M:%S')
                    created_ts = int(time.mktime(created_dt.timetuple()))
                    age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                    if self.opts['age_limit_days'] > 0 and created_ts < age_limit_ts:
                        self.sf.debug("Record found but too old, skipping.")
                        continue
                except BaseException as e:
                    self.sf.debug("Couldn't parse date from Pulsedive so assuming it's OK.")
                e = SpiderFootEvent(evtType, descr, self.__name__, event)
                self.notifyListeners(e)

# End of sfp_pulsedive class
