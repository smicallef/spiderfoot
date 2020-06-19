# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_badpackets
# Purpose:     Spiderfoot plugin to search Bad Packets API for any
#              malicious activity by the target
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     11/05/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
from netaddr import IPNetwork
import urllib.request, urllib.parse, urllib.error
import json

class sfp_badpackets(SpiderFootPlugin):
    """Bad Packets:Investigate,Passive:Reputation Systems:apikey:Obtain information about any malicious activities involving IP addresses found"""

    opts = {
        'api_key': '',
        'checkaffiliates': True,
        'subnetlookup': False,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxsubnet': 24
    }

    # Option descriptions. Delete any options not applicable to this module.
    optdescs = {
        "api_key": "Bad Packets API Key",
        'checkaffiliates': "Check affiliates?",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    results = None
    errorState = False
    limit = 100

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events does this module accept for input
    # For a list of all events, check sfdb.py.
    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER", "NETBLOCK_MEMBER",
                "AFFILIATE_IPADDR"]

    # What events this module produces
    def producedEvents(self):
        return ["IP_ADDRESS", "MALICIOUS_IPADDR", "RAW_RIR_DATA",
                "MALICIOUS_AFFILIATE_IPADDR"]

    # Check whether the IP Address is malicious using Bad Packets API
    # https://docs.badpackets.net/#operation/query
    def queryIPAddress(self, qry, currentOffset):
        params = {
            'source_ip_address': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'limit': self.limit,
            'offset': currentOffset
        }

        headers = {
            'Accept': "application/json",
            'Authorization': "Token " + self.opts['api_key']
        }

        res = self.sf.fetchUrl(
          'https://api.badpackets.net/v1/query?' + urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        return self.parseAPIResponse(res)

    # Parse API Response from Bad Packets
    def parseAPIResponse(self, res):
        if res['content'] is None:
            self.sf.info("No Bad Packets information found")
            return None

        # Error codes as mentioned in Bad Packets Documentation
        if res['code'] == '400':
            self.sf.error("Invalid IP Address", False)
            return None

        if res['code'] == '401':
            self.sf.error("Unauthorized API Key", False)
            return None

        if res['code'] == '403':
            self.sf.error("Forbidden Request", False)
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.sf.error("Failed to retrieve content from Bad Packets", False)
            return None

        # Always always always process external data with try/except since we cannot
        # trust the data is as intended.
        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from Bad Packets.", False)
            return None

        return data

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

        # Always check if the API key is set and complain if it isn't, then set
        # self.errorState to avoid this being a continual complaint during the scan.
        if self.opts['api_key'] == "":
            self.sf.error("You enabled sfp_badpackets but did not set an API key!", False)
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
            # If user has enabled affiliate checking
            if eventName == "AFFILIATE_IPADDR" and not self.opts['checkaffiliates']:
                return None
            qrylist.append(eventData)

        for addr in qrylist:

            nextPageHasData = True
            if self.checkForStop():
                return None

            currentOffset = 0
            while nextPageHasData:
                data = self.queryIPAddress(addr, currentOffset)

                if data is None:
                    nextPageHasData = False
                    break

                count = data.get('count')
                if count is None or int(count) == 0:
                    nextPageHasData = False
                    break

                # Data is reported about the IP Address
                if eventName.startswith("NETBLOCK_"):
                    ipEvt = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                    self.notifyListeners(ipEvt)

                records = data.get('results')
                if records is None:
                    nextPageHasData = False
                    break

                if records:
                    if eventName.startswith("NETBLOCK_"):
                        evt = SpiderFootEvent("RAW_RIR_DATA", str(records), self.__name__, ipEvt)
                        self.notifyListeners(evt)
                    else:
                        evt = SpiderFootEvent("RAW_RIR_DATA", str(records), self.__name__, event)
                        self.notifyListeners(evt)

                    for record in records:
                        maliciousIP = record.get('source_ip_address')

                        if maliciousIP != addr:
                            self.sf.error("Reported address doesn't match requested, skipping.", False)
                            continue

                        if maliciousIP:
                            maliciousIPDesc = "Bad Packets [ " + str(maliciousIP) + " ]\n"

                            try:
                                category = record.get('tags')[0].get('category')
                                if category:
                                    maliciousIPDesc += " - CATEGORY : " + str(category) + "\n"
                            except:
                                self.sf.debug("No category found for target")
                            try:
                                description = record.get('tags')[0].get('description')
                                if description:
                                    maliciousIPDesc += " - DESCRIPTION : " + str(description) + "\n"
                            except:
                                self.sf.debug("No description found for target")

                            maliciousIPDescHash = self.sf.hashstring(maliciousIPDesc)
                            if maliciousIPDescHash in self.results:
                                continue
                            self.results[maliciousIPDescHash] = True

                            # If target is a netblock_ report current IP address as target
                            if eventName.startswith("NETBLOCK_"):
                                evt = SpiderFootEvent("MALICIOUS_IPADDR", maliciousIPDesc, self.__name__, ipEvt)
                            elif eventName.startswith("AFFILIATE_"):
                                evt = SpiderFootEvent("MALICIOUS_AFFILIATE_IPADDR", maliciousIPDesc, self.__name__, event)
                            else:
                                evt = SpiderFootEvent("MALICIOUS_IPADDR", maliciousIPDesc, self.__name__, event)

                            self.notifyListeners(evt)

                if records is None or data.get('count') < self.limit or len(records) < self.limit:
                    nextPageHasData = False
                currentOffset += self.limit

        return None
# End of sfp_badpackets class
