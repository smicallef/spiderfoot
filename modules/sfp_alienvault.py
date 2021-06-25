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
import time
from datetime import datetime

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_alienvault(SpiderFootPlugin):

    meta = {
        'name': "AlienVault OTX",
        'summary': "Obtain information from AlienVault Open Threat Exchange (OTX)",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://otx.alienvault.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://otx.alienvault.com/faq",
                "https://otx.alienvault.com/api",
                "https://otx.alienvault.com/submissions/list",
                "https://otx.alienvault.com/pulse/create",
                "https://otx.alienvault.com/endpoint-security/welcome",
                "https://otx.alienvault.com/browse/"
            ],
            'apiKeyInstructions': [
                "Visit https://otx.alienvault.com/",
                "Sign up for a free account",
                "Navigate to https://otx.alienvault.com/settings",
                "The API key is listed under 'OTX Key'"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://otx.alienvault.com/",
            'logo': "https://otx.alienvault.com/assets/images/otx-logo.svg",
            'description': "The World’s First Truly Open Threat Intelligence Community\n"
            "Open Threat Exchange is the neighborhood watch of the global intelligence community. "
            "It enables private companies, independent security researchers, and government agencies to "
            "openly collaborate and share the latest information about emerging threats, attack methods, "
            "and malicious actors, promoting greater security across the entire community.\n"
            "OTX changed the way the intelligence community creates and consumes threat data. "
            "In OTX, anyone in the security community can contribute, discuss, research, validate, "
            "and share threat data. You can integrate community-generated OTX threat data directly "
            "into your AlienVault and third-party security products, so that your threat detection defenses "
            "are always up to date with the latest threat intelligence. "
            "Today, 100,000 participants in 140 countries contribute over 19 million threat indicators daily."
        }
    }

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

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR",
                "NETBLOCK_OWNER", "NETBLOCK_MEMBER"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_NETBLOCK"]

    def query(self, qry, querytype):
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
            self.sf.error("AlienVault OTX API key seems to have been rejected or you have exceeded usage limits for the month.")
            self.errorState = True
            return None

        if res['content'] is None or res['code'] == "404":
            self.sf.info("No AlienVault OTX info found for " + qry)
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.sf.error(f"Error processing JSON response from AlienVault OTX: {e}")
            return None

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_alienvault but did not set an API key/password!")
            self.errorState = True
            return

        if eventData in self.results:
            self.sf.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                    self.sf.debug("Network size bigger than permitted: "
                                  + str(IPNetwork(eventData).prefixlen) + " > "
                                  + str(self.opts['maxnetblock']))
                    return

        if eventName == 'AFFILIATE_IPADDR' and not self.opts.get('checkaffiliates', False):
            return

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxsubnet']:
                    self.sf.debug("Network size bigger than permitted: "
                                  + str(IPNetwork(eventData).prefixlen) + " > "
                                  + str(self.opts['maxsubnet']))
                    return

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
                        except Exception:
                            self.sf.debug("Couldn't parse date from AlienVault so assuming it's OK.")
                        e = SpiderFootEvent(evtType, host, self.__name__, event)
                        self.notifyListeners(e)

        for addr in qrylist:
            if self.checkForStop():
                return

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
                        except Exception:
                            self.sf.debug("Couldn't parse date from AlienVault so assuming it's OK.")

                    # For netblocks, we need to create the IP address event so that
                    # the threat intel event is more meaningful.
                    if eventName.startswith('NETBLOCK_'):
                        pevent = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                        self.notifyListeners(pevent)
                    else:
                        pevent = event
                    e = SpiderFootEvent(evtType, descr, self.__name__, pevent)
                    self.notifyListeners(e)

# End of sfp_alienvault class
