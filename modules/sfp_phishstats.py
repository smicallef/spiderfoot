# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_phishstats
# Purpose:      Spiderfoot plugin to search PhishStats API
#               to determine if an IP is malicious 
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     18/05/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
from netaddr import IPNetwork
import urllib.request, urllib.parse, urllib.error
import json

class sfp_phishstats(SpiderFootPlugin):
    """PhishStats:Investigate,Passive:Reputation Systems::Determine if an IP Address is malicious"""

    opts = {
        'checkaffiliates': True,
        'subnetlookup': False,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxsubnet': 24
    }

    # Option descriptions. Delete any options not applicable to this module.
    optdescs = {
        'checkaffiliates': "Check affiliates?",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
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

    # Check whether the IP Address is malicious using Phishstats API
    # https://phishstats.info/
    def queryIPAddress(self, qry):
        params = {
            '_where': "(ip,eq," + qry.encode('raw_unicode_escape').decode("ascii", errors='replace') + ")",
            '_size': 1
        }

        headers = {
            'Accept' : "application/json",
        }

        res = self.sf.fetchUrl(
          'https://phishstats.info:2096/api/phishing?' + urllib.parse.urlencode(params),
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        if not res['code'] == "200":
            self.sf.debug("No information found from Phishstats for IP Address")
            return None

        try:
            return json.loads(res['content'])
        except:
            self.sf.error("Ill formatted data received as JSON response", False)
            return None
         
    # Handle events sent to this module
    def handleEvent(self, event):
        
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        
        if self.errorState:
            return None

        self.sf.debug("Received event, %s, from %s" % (eventName, srcModuleName))

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

            if self.checkForStop():
                return None
            
            data = self.queryIPAddress(addr)

            if data is None:
                break
            
            try:
                maliciousIP = data[0].get('ip')
            except:
                # If ArrayIndex is out of bounds then data doesn't exist
                continue
        
            if maliciousIP is None:
                continue

            if addr != maliciousIP:
                self.sf.error("Reported address doesn't match requested, skipping", False)
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

            maliciousIPDesc = "Phishstats [ " + str(maliciousIP) + "]\n"

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

        return None
# End of sfp_phishstats class
