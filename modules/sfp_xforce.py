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

import base64
import json
import time
from datetime import datetime

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_xforce(SpiderFootPlugin):

    meta = {
        'name': "XForce Exchange",
        'summary': "Obtain IP reputation and passive DNS information from IBM X-Force Exchange",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://exchange.xforce.ibmcloud.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://api.xforce.ibmcloud.com/doc/",
                "https://exchange.xforce.ibmcloud.com/faq"
            ],
            'apiKeyInstructions': [
                "Visit https://exchange.xforce.ibmcloud.com",
                "Register a free account",
                "Navigate to https://exchange.xforce.ibmcloud.com/settings",
                "Click on 'API Access'",
                "Provide an API name, and click 'Generate'",
                "The API key combination is listed under 'API Key' and 'API Password'"
            ],
            'favIcon': "https://exchange.xforce.ibmcloud.com/images/shortcut-icons/apple-icon-57x57.png",
            'logo': "https://exchange.xforce.ibmcloud.com/images/shortcut-icons/apple-icon-57x57.png",
            'description': "IBM® X-Force Exchange is a cloud-based, threat intelligence sharing platform that you can use "
            "to rapidly research the latest global security threats, aggregate actionable intelligence, "
            "consult with experts and collaborate with peers. "
            "IBM X-Force Exchange, supported by human- and machine-generated intelligence, "
            "leverages the scale of IBM X-Force to help users stay ahead of emerging threats.",
        }
    }

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
        'cohostsamedomain': False,
        'checkaffiliates': True,
        'verify': True,
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
        "cohostsamedomain": "Treat co-hosted sites on the same target domain as co-hosting?",
        'checkaffiliates': "Apply checks to affiliates?",
        'verify': "Verify identified domains still resolve to the associated specified IP address.",
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

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "AFFILIATE_IPADDR",
                "NETBLOCK_OWNER", "NETBLOCK_MEMBER"]

    # What events this module produces
    def producedEvents(self):
        return ["MALICIOUS_IPADDR", "CO_HOSTED_SITE",
                "MALICIOUS_AFFILIATE_IPADDR", "MALICIOUS_NETBLOCK"]

    def query(self, qry, querytype):
        if querytype not in ["ipr/malware", "ipr/history", "resolve"]:
            querytype = "ipr/malware"

        xforce_url = "https://api.xforce.ibmcloud.com"

        api_key = self.opts['xforce_api_key']
        if type(api_key) == str:
            api_key = api_key.encode('utf-8')
        api_key_password = self.opts['xforce_api_key_password']
        if type(api_key_password) == str:
            api_key_password = api_key_password.encode('utf-8')
        token = base64.b64encode(api_key + ":".encode('utf-8') + api_key_password)
        headers = {
            'Accept': 'application/json',
            'Authorization': "Basic " + token.decode('utf-8')
        }
        url = xforce_url + "/" + querytype + "/" + qry
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], useragent="SpiderFoot", headers=headers)

        return self.parseAPIResponse(res)

    # Parse API Response from X-Force Exchange
    # https://exchange.xforce.ibmcloud.com/api/doc/
    def parseAPIResponse(self, res):
        if res['content'] is None:
            self.sf.info("No X-Force Exchange information found")
            return None

        if res['code'] == '400':
            self.sf.error("Bad request")
            return None

        if res['code'] == '404':
            self.sf.info("No X-Force Exchange information found")
            return None

        if res['code'] == '401':
            self.sf.error("X-Force Exchange API key seems to have been rejected.")
            self.errorState = True
            return None

        if res['code'] == '402':
            self.sf.error("X-Force Exchange monthly quota exceeded")
            self.errorState = True
            return None

        if res['code'] == '403':
            self.sf.error("Access denied")
            self.errorState = True
            return None

        if res['code'] == '429':
            self.sf.error("Rate limit exceeded")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.sf.error("Failed to retrieve content from X-Force Exchange")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.sf.error(f"Error processing JSON response from X-Force Exchange: {e}")

        return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        infield_sep = " ; "

        if self.errorState:
            return

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['xforce_api_key'] == "" or self.opts['xforce_api_key_password'] == "":
            self.sf.error("You enabled sfp_xforce but did not set an API key/password!")
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

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxsubnet']:
                    self.sf.debug("Network size bigger than permitted: "
                                  + str(IPNetwork(eventData).prefixlen) + " > "
                                  + str(self.opts['maxsubnet']))
                    return

        if eventName.startswith('AFFILIATE_') and not self.opts.get('checkaffiliates', False):
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
            if self.cohostcount > self.opts['maxcohost']:
                return

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
                            if not self.opts["cohostsamedomain"]:
                                if self.getTarget().matches(host, includeParents=True):
                                    self.sf.debug(
                                        "Skipping " + host + " because it is on the same domain."
                                    )
                                    continue

                            if self.opts['verify'] and not self.sf.resolveHost(host):
                                continue

                            e = SpiderFootEvent("CO_HOSTED_SITE", host, self.__name__, event)
                            self.notifyListeners(e)
                            self.cohostcount += 1

        for addr in qrylist:
            if self.checkForStop():
                return

            if eventName == 'IP_ADDRESS' or eventName.startswith('NETBLOCK_'):
                evtType = 'MALICIOUS_IPADDR'
            if eventName == "AFFILIATE_IPADDR":
                evtType = 'MALICIOUS_AFFILIATE_IPADDR'

            rec = self.query(addr, "ipr/history")
            if rec is not None:
                rec_history = rec.get("history", list())
                if len(rec_history) > 0:
                    self.sf.debug("Found history results in XForce")
                    for result in rec_history:
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

                        # TODO: use join with infield_sep as delimeter
                        entry = f"{reason}{infield_sep}{score}{infield_sep}{created}{infield_sep}{cats_description}"
                        e = SpiderFootEvent(evtType, entry, self.__name__, event)
                        self.notifyListeners(e)

            rec = self.query(addr, "ipr/malware")
            if rec is not None:
                rec_malware = rec.get("malware", list())
                if len(rec_malware) > 0:
                    self.sf.debug("Found malware results in XForce")
                    for result in rec_malware:
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

                        # TODO: use join with infield_sep as delimeter
                        entry = f"{origin}{infield_sep}{family_description}{infield_sep}{md5}{infield_sep}{domain}{infield_sep}{uri}{infield_sep}{firstseen}{infield_sep}{lastseen}"

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

                        e = SpiderFootEvent(evtType, entry, self.__name__, event)
                        self.notifyListeners(e)

# End of sfp_xforce class
