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

import json
import urllib.error
import urllib.parse
import urllib.request

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_badpackets(SpiderFootPlugin):

    meta = {
        'name': "Bad Packets",
        'summary': "Obtain information about any malicious activities involving IP addresses found",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://badpackets.net",
            'model': "COMMERCIAL_ONLY",
            'references': [
                "https://docs.badpackets.net/"
            ],
            'apiKeyInstructions': [
                "Visit https://badpackets.net/pricing/",
                "Select a monthly plan",
                "Fill out the contact form",
                "BadPackets will reach out to you with your API key"
            ],
            'favIcon': "https://i1.wp.com/badpackets.net/wp-content/uploads/2019/04/cropped-512x512_logo.png?fit=32%2C32&ssl=1",
            'logo': "https://badpackets.net/wp-content/uploads/2019/05/badpackets-rgb-350x70.png",
            'description': "Bad Packets provides cyber threat intelligence on emerging threats, DDoS botnets and network abuse by continuously monitoring "
            "and detecting malicious activity. Our team of experienced security professionals conducts "
            "comprehensive and ethical research to ensure our data is of the highest quality and accuracy.\n"
            "Constant aggregation and analysis of relevant data allows us to empower our partners with "
            "actionable information to proactively defend against emerging security threats.",
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
            self.info("No Bad Packets information found")
            return None

        # Error codes as mentioned in Bad Packets Documentation
        if res['code'] == '400':
            self.error("Invalid IP Address")
            return None

        if res['code'] == '401':
            self.error("Unauthorized API Key")
            return None

        if res['code'] == '403':
            self.error("Forbidden Request")
            return None

        # Catch all non-200 status codes, and presume something went wrong
        if res['code'] != '200':
            self.error("Failed to retrieve content from Bad Packets")
            return None

        # Always always always process external data with try/except since we cannot
        # trust the data is as intended.
        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from Bad Packets: {e}")
            return None

        return None

    # Handle events sent to this module
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
            self.error("You enabled sfp_badpackets but did not set an API key!")
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
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {self.opts['maxnetblock']}")
                return

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return

            if IPNetwork(eventData).prefixlen < self.opts['maxsubnet']:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {self.opts['maxsubnet']}")
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

            nextPageHasData = True
            if self.checkForStop():
                return

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
                            self.error("Reported address doesn't match requested, skipping.")
                            continue

                        if maliciousIP:
                            maliciousIPDesc = "Bad Packets [" + str(maliciousIP) + "]\n"

                            try:
                                category = record.get('tags')[0].get('category')
                                if category:
                                    maliciousIPDesc += " - CATEGORY : " + str(category) + "\n"
                            except Exception:
                                self.debug("No category found for target")

                            try:
                                description = record.get('tags')[0].get('description')
                                if description:
                                    maliciousIPDesc += " - DESCRIPTION : " + str(description) + "\n"
                            except Exception:
                                self.debug("No description found for target")

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

# End of sfp_badpackets class
