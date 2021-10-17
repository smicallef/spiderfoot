# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_xforce
# Purpose:     Obtain IP reputation and passive DNS information from IBM X-Force Exchange.
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
        'summary': "Obtain IP reputation and passive DNS information from IBM X-Force Exchange.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://exchange.xforce.ibmcloud.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://api.xforce.ibmcloud.com/doc/",
                "https://exchange.xforce.ibmcloud.com/faq",
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

    opts = {
        "xforce_api_key": "",
        "xforce_api_key_password": "",
        "age_limit_days": 30,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        'subnetlookup': True,
        'maxsubnet': 24,
        'maxv6subnet': 120,
        'maxcohost': 100,
        'cohostsamedomain': False,
        'checkaffiliates': True,
        'verify': True,
    }

    optdescs = {
        "xforce_api_key": "X-Force Exchange API Key.",
        "xforce_api_key_password": "X-Force Exchange API Password.",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6netblock': "If looking up owned netblocks, the maximum IPv6 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6subnet': "If looking up subnets, the maximum IPv6 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        "cohostsamedomain": "Treat co-hosted sites on the same target domain as co-hosting?",
        'checkaffiliates': "Apply checks to affiliates?",
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
    }

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            'IP_ADDRESS',
            'AFFILIATE_IPADDR',
            'IPV6_ADDRESS',
            'AFFILIATE_IPV6_ADDRESS',
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
        ]

    def producedEvents(self):
        return [
            "BLACKLISTED_IPADDR",
            "BLACKLISTED_AFFILIATE_IPADDR",
            "BLACKLISTED_SUBNET",
            "BLACKLISTED_NETBLOCK",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "DOMAIN_NAME",
            "CO_HOSTED_SITE",
            "RAW_RIR_DATA",
        ]

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
            self.info("No X-Force Exchange information found")
            return None

        if res['code'] == '400':
            self.error("Bad request")
            return None

        if res['code'] == '404':
            self.info("No X-Force Exchange information found")
            return None

        if res['code'] == '401':
            self.error("X-Force Exchange API key seems to have been rejected.")
            self.errorState = True
            return None

        if res['code'] == '402':
            self.error("X-Force Exchange monthly quota exceeded")
            self.errorState = True
            return None

        if res['code'] == '403':
            self.error("Access denied")
            self.errorState = True
            return None

        if res['code'] == '429':
            self.error("Rate limit exceeded")
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error("Failed to retrieve content from X-Force Exchange")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from X-Force Exchange: {e}")

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        eventData = event.data

        infield_sep = " ; "

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {event.module}")

        if self.opts['xforce_api_key'] == "" or self.opts['xforce_api_key_password'] == "":
            self.error("You enabled sfp_xforce but did not set an API key/password!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS']:
            if not self.opts.get('checkaffiliates', False):
                return
            malicious_type = "MALICIOUS_AFFILIATE_IPADDR"
            blacklist_type = "BLACKLISTED_AFFILIATE_IPADDR"
        elif eventName in ["IP_ADDRESS", "IPV6_ADDRESS"]:
            malicious_type = "MALICIOUS_IPADDR"
            blacklist_type = "BLACKLISTED_IPADDR"
        elif eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return

            if eventName == 'NETBLOCKV6_MEMBER':
                max_subnet = self.opts['maxv6subnet']
            else:
                max_subnet = self.opts['maxsubnet']

            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

            malicious_type = "MALICIOUS_SUBNET"
            blacklist_type = "BLACKLISTED_SUBNET"
        elif eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            if eventName == 'NETBLOCKV6_OWNER':
                max_netblock = self.opts['maxv6netblock']
            else:
                max_netblock = self.opts['maxnetblock']

            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

            malicious_type = "MALICIOUS_NETBLOCK"
            blacklist_type = "BLACKLISTED_NETBLOCK"
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        qrylist = list()
        if eventName.startswith("NETBLOCK"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        for addr in qrylist:
            if self.checkForStop():
                return

            rec = self.query(addr, "ipr/history")
            if rec:
                rec_history = rec.get("history", list())
                if len(rec_history) > 0:
                    self.debug(f"Found history results for {addr} in XForce")

                    e = SpiderFootEvent("RAW_RIR_DATA", str(rec_history), self.__name__, event)
                    self.notifyListeners(e)

                    for result in rec_history:
                        created = result.get("created", None)
                        # 2014-11-06T10:45:00.000Z
                        if not created:
                            continue

                        created_dt = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.000Z')
                        created_ts = int(time.mktime(created_dt.timetuple()))
                        age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])
                        if self.opts['age_limit_days'] > 0 and created_ts < age_limit_ts:
                            self.debug(f"Record found but too old ({created_dt}), skipping.")
                            continue

                        reason = result.get("reason", "")
                        score = result.get("score", 0)
                        cats = result.get("cats", [])
                        cats_description = " ".join(cats)

                        if int(score) < 2:
                            self.debug(f"Non-malicious results (score: {score} < 2), skipping.")
                            continue

                        entry = infield_sep.join([str(reason), str(score), str(created), cats_description])

                        text = f"{entry}\n<SFURL>https://exchange.xforce.ibmcloud.com/ip/{addr}</SFURL>"
                        e = SpiderFootEvent(malicious_type, text, self.__name__, event)
                        self.notifyListeners(e)
                        e = SpiderFootEvent(blacklist_type, text, self.__name__, event)
                        self.notifyListeners(e)

            rec = self.query(addr, "ipr/malware")
            if rec:
                rec_malware = rec.get("malware", list())
                if len(rec_malware) > 0:
                    self.debug(f"Found malware results for {addr} in XForce")

                    e = SpiderFootEvent("RAW_RIR_DATA", str(rec_malware), self.__name__, event)
                    self.notifyListeners(e)

                    for result in rec_malware:
                        origin = result.get("origin", "")
                        domain = result.get("domain", "")
                        uri = result.get("uri", "")
                        md5 = result.get("md5", "")
                        lastseen = result.get("last", "")
                        firstseen = result.get("first", "")
                        family = result.get("family", [])
                        family_description = " ".join(family)

                        entry = infield_sep.join([str(origin), family_description, str(md5), str(domain), str(uri), str(firstseen), str(lastseen)])

                        last = rec.get("last", None)

                        if not last:
                            continue

                        last_dt = datetime.strptime(last, '%Y-%m-%dT%H:%M:%S.000Z')
                        last_ts = int(time.mktime(last_dt.timetuple()))
                        age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])

                        if self.opts['age_limit_days'] > 0 and last_ts < age_limit_ts:
                            self.debug(f"Record found but too old ({last_dt}), skipping.")
                            continue

                        text = f"{entry}\n<SFURL>https://exchange.xforce.ibmcloud.com/ip/{addr}</SFURL>"
                        e = SpiderFootEvent(malicious_type, text, self.__name__, event)
                        self.notifyListeners(e)
                        e = SpiderFootEvent(blacklist_type, text, self.__name__, event)
                        self.notifyListeners(e)

        # For IP addresses, do the additional passive DNS lookup
        # TODO: Add this to the loop above to support netblocks
        if eventName in ["IP_ADDRESS", "IPV6_ADDRESS"]:
            if self.cohostcount >= self.opts['maxcohost']:
                return

            ret = self.query(eventData, "resolve")
            if not ret:
                self.info(f"No Passive DNS info for {eventData}")
                return

            passive = ret.get('Passive')
            if not passive:
                return

            records = passive.get('records')
            if not records:
                return

            self.debug(f"Found passive DNS results for {eventData} in Xforce")

            e = SpiderFootEvent("RAW_RIR_DATA", str(records), self.__name__, event)
            self.notifyListeners(e)

            for rec in records:
                if self.checkForStop():
                    return

                if rec['recordType'] == "A":
                    last = rec.get("last", None)

                    if not last:
                        continue

                    host = rec.get('value')
                    if not host:
                        continue

                    last_dt = datetime.strptime(last, '%Y-%m-%dT%H:%M:%SZ')
                    last_ts = int(time.mktime(last_dt.timetuple()))
                    age_limit_ts = int(time.time()) - (86400 * self.opts['age_limit_days'])

                    if self.opts['verify']:
                        if not self.sf.validateIP(host, eventData):
                            self.debug(f"Host {host} no longer resolves to {eventData}")
                            continue
                    else:
                        if self.opts['age_limit_days'] > 0 and last_ts < age_limit_ts:
                            self.debug(f"Record found but too old ({last_dt}), skipping.")
                            continue

                    if not self.opts["cohostsamedomain"]:
                        if self.getTarget().matches(host, includeParents=True):
                            if self.sf.resolveHost(host) or self.sf.resolveHost6(host):
                                e = SpiderFootEvent("INTERNET_NAME", host, self.__name__, event)
                            else:
                                e = SpiderFootEvent("INTERNET_NAME_UNRESOLVED", host, self.__name__, event)
                            self.notifyListeners(e)

                            if self.sf.isDomain(host, self.opts['_internettlds']):
                                e = SpiderFootEvent("DOMAIN_NAME", host, self.__name__, event)
                                self.notifyListeners(e)
                            continue

                    e = SpiderFootEvent("CO_HOSTED_SITE", host, self.__name__, event)
                    self.notifyListeners(e)
                    self.cohostcount += 1

# End of sfp_xforce class
