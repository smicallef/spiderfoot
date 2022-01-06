# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_threatminer
# Purpose:      Query ThreatMiner.org using their API.
#
# Author:      Steve Micallef
#
# Created:     12/07/2019
# Copyright:   (c) Steve Micallef 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
from datetime import datetime

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_threatminer(SpiderFootPlugin):

    meta = {
        'name': "ThreatMiner",
        'summary': "Obtain information from ThreatMiner's database for passive DNS and threat intelligence.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.threatminer.org/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://www.threatminer.org/api.php",
                "https://www.threatminer.org/features.php"
            ],
            'favIcon': "https://www.threatminer.org/images/favicon.gif",
            'logo': "https://www.threatminer.org/images/logo.png",
            'description': "ThreatMiner is a threat intelligence portal designed to enable analysts to research under a single interface. "
            "It is used in the SANS FOR578 Cyber Threat Intelligence course.\n"
            "Threat intelligence and intrusion analysts who regularly perform research "
            "into malware and network infrastructure often find the need to rely on "
            "mutliple websites that individually holds a small piece of the larger puzzle.",
        }
    }
    # Default options
    opts = {
        'verify': True,
        'netblocklookup': False,
        'maxnetblock': 24,
        'subnetlookup': False,
        'maxsubnet': 24,
        'maxcohost': 100,
        "age_limit_days": 90
    }

    # Option descriptions
    optdescs = {
        'verify': 'Verify that any hostnames found on the target domain still resolve?',
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        "age_limit_days": "Ignore records older than this many days. 0 = Unlimited."
    }

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

    results = None
    cohostcount = 0
    reportedhosts = None
    checkedips = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.reportedhosts = self.tempStorage()
        self.checkedips = self.tempStorage()
        self.cohostcount = 0

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "DOMAIN_NAME", "NETBLOCK_OWNER",
                "NETBLOCK_MEMBER"]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME", "CO_HOSTED_SITE"]

    def query(self, qry, querytype):
        if self.sf.validIP(qry):
            tgttype = "host"
        else:
            tgttype = "domain"

        if querytype == "subs":
            queryurl = "/v2/" + tgttype + ".php?q={0}&rt=5"
        if querytype == "passive":
            queryurl = "/v2/" + tgttype + ".php?q={0}&rt=2"

        threatminerurl = "https://api.threatminer.org"
        url = threatminerurl + queryurl.format(qry)
        res = self.sf.fetchUrl(url, timeout=10, useragent="SpiderFoot")

        if res['content'] is None:
            self.info("No ThreatMiner info found for " + qry)
            return None

        if len(res['content']) == 0:
            self.info("No ThreatMiner info found for " + qry)
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from ThreatMiner: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return
            if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                self.debug("Network size bigger than permitted: "
                           + str(IPNetwork(eventData).prefixlen) + " > "
                           + str(self.opts['maxnetblock']))
                return

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return
            if IPNetwork(eventData).prefixlen < self.opts['maxsubnet']:
                self.debug("Network size bigger than permitted: "
                           + str(IPNetwork(eventData).prefixlen) + " > "
                           + str(self.opts['maxsubnet']))
                return

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True

        if eventName == "IP_ADDRESS":
            qrylist.append(eventData)

        # qrylist now contains all IPs we want to look up
        for qry in qrylist:
            evtType = "CO_HOSTED_SITE"
            ret = self.query(qry, "passive")
            if ret is None:
                self.info("No Passive DNS info for " + qry)
                return

            if "results" not in ret:
                continue
            if len(ret['results']) == 0:
                continue

            self.debug("Found passive DNS results in ThreatMiner")
            res = ret["results"]
            for rec in res:
                # Skip stuff with no date
                if rec.get('last_seen') == '':
                    continue
                last_seen = datetime.strptime(rec.get('last_seen', "1970-01-01 00:00:00"), '%Y-%m-%d %H:%M:%S')
                last_ts = int(time.mktime(last_seen.timetuple()))
                age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                if self.opts['age_limit_days'] > 0 and last_ts < age_limit_ts:
                    self.debug("Record found but too old, skipping.")
                    continue

                host = rec['domain']
                if host == eventData:
                    continue
                if self.getTarget().matches(host, includeParents=True):
                    if self.opts['verify'] and not self.sf.resolveHost(host) and not self.sf.resolveHost6(host):
                        evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, event)
                    else:
                        evt = SpiderFootEvent("INTERNET_NAME", host, self.__name__, event)
                    self.notifyListeners(evt)
                    self.reportedhosts[host] = True
                    continue

                if self.cohostcount < self.opts['maxcohost']:
                    e = SpiderFootEvent(evtType, host, self.__name__, event)
                    self.notifyListeners(e)
                    self.cohostcount += 1

        if eventName == "DOMAIN_NAME":
            evtType = "INTERNET_NAME"
            ret = self.query(eventData, "subs")
            if ret is None:
                self.debug("No hosts found")
                return

            if len(ret.get("results", list())) == 0:
                self.debug("No hosts found")
                return

            for host in ret.get("results"):
                self.debug("Found host results in ThreatMiner")

                if host in self.reportedhosts:
                    continue

                self.reportedhosts[host] = True

                if self.opts['verify'] and not self.sf.resolveHost(host) and not self.sf.resolveHost6(host):
                    evt = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, event)
                else:
                    evt = SpiderFootEvent("INTERNET_NAME", host, self.__name__, event)
                evt = SpiderFootEvent(evtType, host, self.__name__, event)
                self.notifyListeners(evt)

# End of sfp_threatminer class
