# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_spur
# Purpose:      Spiderfoot plugin to search spur.us API for any 
#               malicious activity by the target
#
# Author:      Krishnasis Mandal <krishnasis@hotmail.com>
#
# Created:     12/06/2020
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent
from netaddr import IPNetwork
import json

class sfp_spur(SpiderFootPlugin):
    """spur.us:Investigate,Passive:Reputation Systems:apikey:Obtain information about any malicious activities involving IP addresses found"""

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
        "api_key": "spur.us API Key",
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
            "GEO_INFO", "COMPANY_NAME", "MALICIOUS_AFFILIATE_IPADDR"]
    
    # Check whether the IP Address is malicious using spur.us API
    # https://spur.us/app/docs
    def queryIPAddress(self, ipAddr):

        headers = {
            'Accept': "application/json",
            'token': self.opts['api_key']
        }

        res = self.sf.fetchUrl(
          'https://api.spur.us/v1/context/' + ipAddr,
          headers=headers,
          timeout=15,
          useragent=self.opts['_useragent']
        )

        code = res.get('code')

        if code == '403':
            self.sf.error("Invalid credentials. Please check API Token", False)
            self.errorState = True
            return None
        
        if code == '404':
            self.sf.debug("IP Address not found.")
            return None

        if not code == '200':
            self.sf.error("Unable to fetch data from spur.us", False)
            return None
        
        content = res.get('content')

        return content

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
            self.sf.error("You enabled sfp_spur but did not set an API key!", False)
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

            if self.checkForStop():
                return None
            
            content = self.queryIPAddress(addr)

            if content is None:
                continue
                
            data = json.loads(content)
            
            if eventName.startswith("NETBLOCK_"):
                ipEvt = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(evt)

            if eventName.startswith("NETBLOCK_"):
                evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, ipEvt)
                self.notifyListeners(evt)
            else:
                evt = SpiderFootEvent("RAW_RIR_DATA", str(data), self.__name__, event)
                self.notifyListeners(evt)

            geoTag = data.get('geoLite')

            if geoTag:
                city = geoTag.get('city')
                country = geoTag.get('country')
                state = geoTag.get('state')

                geoInfo = ""
                if city:
                    geoInfo += city + ", "
                
                if state:
                    geoInfo += state + ", "
                
                if country:
                    geoInfo += country
                
                if eventName.startswith("NETBLOCK_"):
                    evt = SpiderFootEvent("GEOINFO", geoInfo, self.__name__, ipEvt)
                    self.notifyListeners(evt)
                elif eventName.startswith("AFFILIATE_"):
                    # Don't report GEOINFO for Affiliates
                    pass
                else:
                    evt = SpiderFootEvent("GEOINFO", geoInfo, self.__name__, event)
                    self.notifyListeners(evt)
            
            asData = data.get('as')

            if asData:
                orgName = asData.get('organization')  

                if orgName:
                    if eventName.startswith("NETBLOCK_"):
                        evt = SpiderFootEvent("COMPANY_NAME", orgName, self.__name__, ipEvt)
                        self.notifyListeners(evt)
                    elif eventName.startswith("AFFILIATE_"):
                        # Don't report COMPANY_NAME for Affiliates
                        pass
                    else:
                        evt = SpiderFootEvent("COMPANY_NAME", orgName, self.__name__, event)
                        self.notifyListeners(evt)
            
            vpnOperators = data.get('vpnOperators')
            
            vpnOperatorsExists = vpnOperators.get('exists')

            if vpnOperatorsExists:
                vpnOperatorNames = vpnOperators.get('operators')

                maliciousIPDesc = "spur.us [ " + str(addr) + " ]\n"
                maliciousIPDesc += "VPN Operators : "

                for operatorNameDict in vpnOperatorNames:
                    operatorName = operatorNameDict.get('name')

                    if operatorName:
                        maliciousIPDesc += operatorName + ", "

                maliciousIPDesc = maliciousIPDesc.strip(", ")

                if eventName.startswith("NETBLOCK_"):
                    evt = SpiderFootEvent("MALICIOUS_IPADDR", maliciousIPDesc, self.__name__, ipEvt)
                    self.notifyListeners(evt)
                elif eventName.startswith("AFFILIATE_"):
                    evt = SpiderFootEvent("MALICIOUS_AFFILIATE_IPADDR", maliciousIPDesc, self.__name__, event)
                    self.notifyListeners(evt)
                else:
                    evt = SpiderFootEvent("MALICIOUS_IPADDR", maliciousIPDesc, self.__name__, event)
                    self.notifyListeners(evt)
        
        return None

# End of sfp_spur class
