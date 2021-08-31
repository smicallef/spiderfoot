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

import base64
import json
import time
from datetime import datetime

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_fraudguard(SpiderFootPlugin):

    meta = {
        'name': "Fraudguard",
        'summary': "Obtain threat information from Fraudguard.io",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://fraudguard.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.fraudguard.io/",
                "https://faq.fraudguard.io/"
            ],
            'apiKeyInstructions': [
                "Visit https://app.fraudguard.io/register",
                "Register a free account",
                "Navigate to https://app.fraudguard.io/keys",
                "The API key combination is listed under Username and Password"
            ],
            'favIcon': "https://fraudguard.io/img/favicon.ico",
            'logo': "https://s3.amazonaws.com/fraudguard.io/img/header.png",
            'description': "FraudGuard is a service designed to provide an easy way to validate usage "
            "by continuously collecting and analyzing real-time internet traffic. "
            "Utilizing just a few simple API endpoints we make integration as simple as possible "
            "and return data such as: Risk Level, Threat Type, Geo Location, etc. Super fast, super simple.\n"
            "Lookup any IP address by querying our threat engine.",
        }
    }

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
        "fraudguard_api_key_account": "Fraudguard.io API username.",
        "fraudguard_api_key_password": "Fraudguard.io API password.",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
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

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER"]

    # What events this module produces
    def producedEvents(self):
        return ["GEOINFO", "MALICIOUS_IPADDR", "MALICIOUS_NETBLOCK"]

    def query(self, qry):
        fraudguard_url = "https://api.fraudguard.io/ip/" + qry
        api_key_account = self.opts['fraudguard_api_key_account']
        if type(api_key_account) == str:
            api_key_account = api_key_account.encode('utf-8')
        api_key_password = self.opts['fraudguard_api_key_password']
        if type(api_key_password) == str:
            api_key_password = api_key_password.encode('utf-8')
        token = base64.b64encode(api_key_account + ':'.encode('utf-8') + api_key_password)
        headers = {
            'Authorization': "Basic " + token.decode('utf-8')
        }

        res = self.sf.fetchUrl(fraudguard_url, timeout=self.opts['_fetchtimeout'],
                               useragent="SpiderFoot", headers=headers)

        if res['code'] in ["400", "429", "500", "403"]:
            self.sf.error("Fraudguard.io API key seems to have been rejected or you have exceeded usage limits for the month.")
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.info("No Fraudguard.io info found for " + qry)
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.sf.error(f"Error processing JSON response from Fraudguard.io: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['fraudguard_api_key_account'] == "" or self.opts['fraudguard_api_key_password'] == "":
            self.sf.error("You enabled sfp_fraudguard but did not set an API username/password!")
            self.errorState = True
            return

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return
            if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                self.sf.debug("Network size bigger than permitted: "
                              + str(IPNetwork(eventData).prefixlen) + " > "
                              + str(self.opts['maxnetblock']))
                return

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
                return

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

                # For netblocks, we need to create the IP address event so that
                # the threat intel event is more meaningful.
                if eventName.startswith('NETBLOCK_'):
                    pevent = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                    self.notifyListeners(pevent)
                else:
                    pevent = event

                if "unknown" not in [rec['country'], rec['state'], rec['city']]:
                    dat = rec['country'] + ", " + rec['state'] + ", " + rec['city']
                    e = SpiderFootEvent("GEOINFO", dat, self.__name__, pevent)
                    self.notifyListeners(e)

                if rec.get('threat') != "unknown":
                    dat = rec['threat'] + " (risk level: " + rec['risk_level'] + ") [" + eventData + "]"
                    e = SpiderFootEvent("MALICIOUS_" + rtype, dat, self.__name__, pevent)
                    self.notifyListeners(e)

# End of sfp_fraudguard class
