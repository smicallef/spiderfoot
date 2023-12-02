# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_internetdb
# Purpose:     Search the InternetDB API for information about IP addresses.
#
# Author:      Justin Sohl 
#
# Created:     2/12/2023
# Copyright:   (c) Steve Micallef
# Licence:     MIT
# -------------------------------------------------------------------------------

import json
import time

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_internetdb(SpiderFootPlugin):

    meta = {
        'name': "InternetDB",
        'summary': "Obtain information from the InternetDB API about identified IP addresses.",
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://internetdb.shodan.io/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://internetdb.shodan.io/",
                "https://internetdb.shodan.io/docs"
            ],
            'favIcon': "https://static.shodan.io/shodan/img/favicon.png",
            'logo': "https://static.shodan.io/developer/img/logo.png",
            'description': "The InternetDB API provides a fast way to see the open ports for an IP address."
            "It gives a quick, at-a-glance view of the type of device that is running behind an IP address to help you make decisions based on the open ports.",
        }
    }

    # Default options
    opts = {
        'netblocklookup': True,
        'maxnetblock': 24
    }

    # Option descriptions
    optdescs = {
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER"]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME",
                'IP_ADDRESS', 
                'RAW_RIR_DATA', 
                "TCP_PORT_OPEN", 
                'VULNERABILITY_CVE_CRITICAL',
                'VULNERABILITY_CVE_HIGH', 
                'VULNERABILITY_CVE_MEDIUM',
                'VULNERABILITY_CVE_LOW', 
                'VULNERABILITY_GENERAL']

    def queryHost(self, qry):
        res = self.sf.fetchUrl(
            f"https://internetdb.shodan.io/{qry}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )
        time.sleep(1)

        # InternetDB does not document a rate limit, but they might implement one
        if res['code'] in ["403", "401"]:
            self.error("You have exceeded usage limits.")
            self.errorState = True
            return None

        if res['code'] == "404" or res['content'] is None:
            self.info(f"No InternetDB info found for {qry}")
            return None
        
        if res['code'] == "422":
            self.error(f"Validation error for {qry}")

        try:
            r = json.loads(res['content'])
            if "error" in r:
                self.error(f"Error returned from InternetDB: {r['error']}")
                return None
            return r
        except Exception as e:
            self.error(f"Error processing JSON response from InternetDB: {e}")
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

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return
            max_netblock = self.opts['maxnetblock']
            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        for addr in qrylist:
            rec = self.queryHost(addr)
            if rec is None:
                continue

            # For netblocks, we need to create the IP address event so that
            # the threat intel event is more meaningful.
            if eventName == 'NETBLOCK_OWNER':
                pevent = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                self.notifyListeners(pevent)
            else:
                pevent = event

            evt = SpiderFootEvent("RAW_RIR_DATA", str(rec), self.__name__, pevent)
            self.notifyListeners(evt)

            if self.checkForStop():
                return

            self.info(f"Found InternetDB data for {eventData}")
            ports = rec.get('ports')
            vulns = rec.get('vulns')
            hostnames = rec.get('hostnames')

            for port in ports:
                cp = addr + ":" + str(port)
                # InternetDB does not specify TCP or UDP, however, there is no generic PORT_OPEN event.
                evt = SpiderFootEvent("TCP_PORT_OPEN", cp, self.__name__, pevent)
                self.notifyListeners(evt)

            for vuln in vulns:
                etype, cvetext = self.sf.cveInfo(vuln)
                evt = SpiderFootEvent(etype, cvetext, self.__name__, pevent)
                self.notifyListeners(evt)

            for hostname in hostnames:
                evt = SpiderFootEvent("INTERNET_NAME", hostname, self.__name__, pevent)
                self.notifyListeners(evt)

# End of sfp_internetdb class
