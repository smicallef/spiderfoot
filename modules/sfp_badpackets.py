# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_badpackets
# Purpose:      Spiderfoot plugin to search BadPackets API for any 
#               malicious activity by the target
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
    
    """Bad Packets:Footprint,Investigate,Passive:Search Engines:apikey:Obtain information for any malicious activities by target"""

    opts = {
        'api_key': '',
        'checkcohosts': True,
        'checkaffiliates': True,
        'subnetlookup': False,
        'netblocklookup': True,
        'maxsubnet': 24,
        'maxnetblock': 24,
        'maxcohost': 100,
        'verify': True,
        "cohostsamedomain": False
    }

    # Option descriptions. Delete any options not applicable to this module.
    optdescs = {
        "api_key": "Bad packets API Key",
        'checkcohosts': "Check co-hosted sites?",
        'checkaffiliates': "Check affiliates?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        "cohostsamedomain": "Treat co-hosted sites on the same target domain as co-hosting?",
        'verify': 'Verify that any hostnames found on the target domain still resolve?'

    }

    results = None

    errorState = False  
    limit = 100

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]
        

    # What events is this module interested in for input
    # For a list of all events, check sfdb.py.
    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER", "NETBLOCK_MEMBER"]

    # What events this module produces
    def producedEvents(self):
        return ["IP_ADDRESS", "MALICIOUS_IPADDR", "RAW_RIR_DATA",
            "COUNTRY_NAME", "DESCRIPTION_CATEGORY", "DESCRIPTION_ABSTRACT"]

    # Check whether the IP Address is malicious using Bad Packets API
    def queryIPAddress(self, qry, currentOffset):
        params = {
            'source_ip_address': qry.encode('raw_unicode_escape').decode("ascii", errors='replace'),
            'limit': self.limit, 
            'offset': currentOffset
        }

        headers = {
            'Accept' : "application/json",
            'Authorization' : "Token " + self.opts['api_key']
        }

        res = self.sf.fetchUrl(
          'https://api.badpackets.net/v1/query?' + urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        return self.parseAPIResponse(res)
        
    # Parse API Response from Badpackets
    def parseAPIResponse(self, res):
        if res['content'] is None:
            self.sf.info("No Bad Packets information found")
            return None

        if res['code'] == '400':
            self.sf.error("Invalid IP Address", False)
            self.errorState = True
            return None

        if res['code'] == '401':
            self.sf.error("Unauthorized API Key", False)
            self.errorState = True
            return None

        if res['code'] == '403':
            self.sf.error("Forbidden Request", False)
            self.errorState = True
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.sf.error("Failed to retrieve content from Spyse", False)
            self.errorState = True
            return None

        # Always always always process external data with try/except since we cannot
        # trust the data is as intended.
        try:
            data = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from BadPackets.", False)
            return None

        return data
    
    def reportExtraData(self, event, result):

        # Report category of target
        category = result.get('tags')[0].get('category')
        if category:
            evt = SpiderFootEvent("DESCRIPTION_CATEGORY", str(category), self.__name__, event)
            self.notifyListeners(evt)
        
        # Report description of target
        description = result.get('tags')[0].get('description')
        if description:
            evt = SpiderFootEvent("DESCRIPTION_ABSTRACT", str(description), self.__name__, event)
            self.notifyListeners(evt)



    # Handle events sent to this module
    def handleEvent(self, event):
        try:
            eventName = event.eventType
            srcModuleName = event.module
            eventData = event.data
            
            if self.errorState:
                return None

            self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

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

                    # Note ::::: count might not be there. Add failsafe 
                    if data.get('count') == 0:
                        nextPageHasData = False
                        break

                    # Data is returned about the IP Address
                    evt = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                    self.notifyListeners(evt)

                    results = data.get('results')
                    for result in results:
                        evt = SpiderFootEvent("RAW_RIR_DATA", str(result), self.__name__, event)
                        self.notifyListeners(evt)
                        self.reportExtraData(event, result)

                        maliciousIP = result.get('source_ip_address')
                        # Note :::::::::::::::::::::
                        # Possible chance of duplication - Check this with a larger sample
                        if maliciousIP:
                            evt = SpiderFootEvent("MALICIOUS_IPADDR", str(maliciousIP), self.__name__, event)
                            self.notifyListeners(evt)

                    if data.get('count') < self.limit or len(results) < self.limit:
                        nextPageHasData = False
                    currentOffset += self.limit
            
            return None
        except Exception as e:
            self.sf.error("An exception occured :: " + str(e))
# End of sfp_badpackets class
