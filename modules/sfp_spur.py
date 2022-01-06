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

import json

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_spur(SpiderFootPlugin):

    meta = {
        'name': "spur.us",
        'summary': "Obtain information about any malicious activities involving IP addresses found",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://spur.us/",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://spur.us/api"
            ],
            'apiKeyInstructions': [
                "Visit https://spur.us",
                "Register an account",
                "Pay for a subscription",
                "Navigate to https://spur.us/app/context/tokens",
                "The API key is listed under 'Token'"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://spur.us",
            'logo': "https://spur.us/app/horizontal_logo.svg",
            'description': "We expose VPNs, residential proxies, botnets, anonymization behavior, geo-fraud, and more. "
            "Anonymous infrastructure has changed; it is time the security industry caught up.\n"
            "Identify commercial and private VPN exit points along with the name of the service. "
            "We expose over 80 different commercial providers.",
        }
    }

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
        return [
            "IP_ADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCK_MEMBER",
            "AFFILIATE_IPADDR"
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            "IP_ADDRESS",
            "MALICIOUS_IPADDR",
            "RAW_RIR_DATA",
            "GEOINFO",
            "COMPANY_NAME",
            "MALICIOUS_AFFILIATE_IPADDR"
        ]

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
            self.error("Invalid credentials. Please check API Token")
            self.errorState = True
            return None

        if code == '404':
            self.debug("IP Address not found.")
            return None

        if code != '200':
            self.error("Unable to fetch data from spur.us")
            return None

        return res.get('content')

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Always check if the API key is set and complain if it isn't, then set
        # self.errorState to avoid this being a continual complaint during the scan.
        if self.opts['api_key'] == "":
            self.error("You enabled sfp_spur but did not set an API key!")
            self.errorState = True
            return

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

            content = self.queryIPAddress(addr)

            if content is None:
                continue

            data = json.loads(content)

            # For netblocks, create the event for the IP address to link to later
            if eventName.startswith("NETBLOCK_"):
                ipEvt = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(ipEvt)
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

                maliciousIPDesc = "spur.us [" + str(addr) + "]\n"
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

# End of sfp_spur class
