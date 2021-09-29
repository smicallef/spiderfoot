# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_maltiverse
# Purpose:      Spiderfoot plugin to search Maltiverse API
#               for any malicious activity by the target
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     20/05/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
from datetime import datetime

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_maltiverse(SpiderFootPlugin):

    meta = {
        'name': "Maltiverse",
        'summary': "Obtain information about any malicious activities involving IP addresses",
        'flags': [],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://maltiverse.com",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://maltiverse.com/faq",
                "https://app.swaggerhub.com/apis-docs/maltiverse/api/1.0.0-oas3"
            ],
            'favIcon': "https://maltiverse.com/favicon.ico",
            'logo': "https://maltiverse.com/assets/images/logo/logo.png",
            'description': "The Open IOC Search Engine.\n"
                           "Enhance your SIEM or Firewall and crosscheck your event data with "
                           "top quality Threat Intelligence information to highlight what requires action.",
        }
    }

    opts = {
        'checkaffiliates': True,
        'subnetlookup': False,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxsubnet': 24,
        "age_limit_days": 30
    }

    # Option descriptions. Delete any options not applicable to this module.
    optdescs = {
        'checkaffiliates': "Check affiliates?",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        "age_limit_days": "Ignore any records older than this many days. 0 = unlimited.",
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    # For a list of all events, check sfdb.py.
    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER", "NETBLOCK_MEMBER",
                "AFFILIATE_IPADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["IP_ADDRESS", "MALICIOUS_IPADDR", "RAW_RIR_DATA",
                "MALICIOUS_AFFILIATE_IPADDR"]

    # Check whether the IP Address is malicious using Maltiverse API
    # https://app.swaggerhub.com/apis-docs/maltiverse/api/1.0.0-oas3#/IPv4/getIP
    def queryIPAddress(self, qry):

        headers = {
            'Accept': "application/json",
        }

        res = self.sf.fetchUrl(
            'https://api.maltiverse.com/ip/' + str(qry),
            headers=headers,
            timeout=15,
            useragent=self.opts['_useragent']
        )

        if res['code'] == "400":
            self.error("Bad request. " + qry + " is not a valid IP Address")
            return None

        if res['code'] == "404":
            self.error("API endpoint not found")
            return None

        if res['code'] != "200":
            self.debug("No information found from Maltiverse for IP Address")
            return None

        try:
            # Maltiverse returns \\n instead of \n in the response
            data = str(res['content']).replace("\\n", " ")
            return json.loads(data)
        except Exception:
            self.error("Incorrectly formatted data received as JSON response")
            return None

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Don't look up stuff twice
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
        else:
            # If user has enabled affiliate checking
            if eventName == "AFFILIATE_IPADDR" and not self.opts['checkaffiliates']:
                return
            qrylist.append(eventData)

        for addr in qrylist:

            if self.checkForStop():
                return

            data = self.queryIPAddress(addr)

            if data is None:
                break

            maliciousIP = data.get('ip_addr')

            if maliciousIP is None:
                continue

            if addr != maliciousIP:
                self.error("Reported address doesn't match requested, skipping")
                continue

            blacklistedRecords = data.get('blacklist')

            if blacklistedRecords is None or len(blacklistedRecords) == 0:
                self.debug("No blacklist information found for IP")
                continue

            # Data is reported about the IP Address
            if eventName.startswith("NETBLOCK_"):
                ipEvt = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(ipEvt)

            if eventName.startswith("NETBLOCK_"):
                evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, ipEvt)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
                self.notifyListeners(evt)

            maliciousIPDesc = f"Maltiverse [{maliciousIP}]\n"

            for blacklistedRecord in blacklistedRecords:
                lastSeen = blacklistedRecord.get('last_seen')
                if lastSeen is None:
                    continue

                try:
                    lastSeenDate = datetime.strptime(str(lastSeen), "%Y-%m-%d %H:%M:%S")
                except Exception:
                    self.error("Invalid date in JSON response, skipping")
                    continue

                today = datetime.now()

                difference = (today - lastSeenDate).days

                if difference > int(self.opts["age_limit_days"]):
                    self.debug("Record found is older than age limit, skipping")
                    continue

                maliciousIPDesc += " - DESCRIPTION : " + str(blacklistedRecord.get("description")) + "\n"

            maliciousIPDescHash = self.sf.hashstring(maliciousIPDesc)

            if maliciousIPDescHash in self.results:
                continue

            self.results[maliciousIPDescHash] = True

            if eventName.startswith("NETBLOCK_"):
                evt = SpiderFootEvent("MALICIOUS_IPADDR", maliciousIPDesc, self.__name__, ipEvt)
            elif eventName.startswith("AFFILIATE_"):
                evt = SpiderFootEvent("MALICIOUS_AFFILIATE_IPADDR", maliciousIPDesc, self.__name__, event)
            else:
                evt = SpiderFootEvent("MALICIOUS_IPADDR", maliciousIPDesc, self.__name__, event)

            self.notifyListeners(evt)

# End of sfp_maltiverse class
