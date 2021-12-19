# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:        sfp_shodan
# Purpose:     Search Shodan for information related to the target.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     19/03/2014
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_shodan(SpiderFootPlugin):

    meta = {
        'name': "SHODAN",
        'summary': "Obtain information from SHODAN about identified IP addresses.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.shodan.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://developer.shodan.io/api",
                "https://developer.shodan.io/apps"
            ],
            'apiKeyInstructions': [
                "Visit https://shodan.io",
                "Register a free account",
                "Navigate to https://account.shodan.io/",
                "The API key is listed under 'API Key'"
            ],
            'favIcon': "https://static.shodan.io/shodan/img/favicon.png",
            'logo': "https://static.shodan.io/developer/img/logo.png",
            'description': "Shodan is the world's first search engine for Internet-connected devices.\n"
            "Use Shodan to discover which of your devices are connected to the Internet, where they are located and who is using them."
            "Keep track of all the computers on your network that are directly accessible from the Internet. "
            "Shodan lets you understand your digital footprint.",
        }
    }

    # Default options
    opts = {
        'api_key': "",
        'netblocklookup': True,
        'maxnetblock': 24
    }

    # Option descriptions
    optdescs = {
        "api_key": "SHODAN API Key.",
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
        return ["IP_ADDRESS", "NETBLOCK_OWNER", "DOMAIN_NAME", "WEB_ANALYTICS_ID"]

    # What events this module produces
    def producedEvents(self):
        return ["OPERATING_SYSTEM", "DEVICE_TYPE",
                "TCP_PORT_OPEN", "TCP_PORT_OPEN_BANNER",
                'RAW_RIR_DATA', 'GEOINFO',
                'VULNERABILITY_CVE_CRITICAL',
                'VULNERABILITY_CVE_HIGH', 'VULNERABILITY_CVE_MEDIUM',
                'VULNERABILITY_CVE_LOW', 'VULNERABILITY_GENERAL']

    def queryHost(self, qry):
        res = self.sf.fetchUrl(
            f"https://api.shodan.io/shodan/host/{qry}?key={self.opts['api_key']}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )
        time.sleep(1)

        if res['content'] is None:
            self.info(f"No SHODAN info found for {qry}")
            return None

        try:
            r = json.loads(res['content'])
            if "error" in r:
                self.error(f"Error returned from SHODAN: {r['error']}")
                return None
            return r
        except Exception as e:
            self.error(f"Error processing JSON response from SHODAN: {e}")
            return None

        return None

    def searchHosts(self, qry):
        params = {
            'query': f"hostname:{qry}",
            'key': self.opts['api_key']
        }

        res = self.sf.fetchUrl(
            f"https://api.shodan.io/shodan/host/search?{urllib.parse.urlencode(params)}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )
        time.sleep(1)
        if res['content'] is None:
            self.info(f"No SHODAN info found for {qry}")
            return None

        try:
            r = json.loads(res['content'])
            if "error" in r:
                self.error(f"Error returned from SHODAN: {r['error']}")
                return None
            return r
        except Exception as e:
            self.error(f"Error processing JSON response from SHODAN: {e}")
            return None

        return None

    def searchHtml(self, qry):
        params = {
            'query': 'http.html:"' + qry.encode('raw_unicode_escape').decode("ascii", errors='replace') + '"',
            'key': self.opts['api_key']
        }

        res = self.sf.fetchUrl(
            f"https://api.shodan.io/shodan/host/search?{urllib.parse.urlencode(params)}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )
        time.sleep(1)
        if res['content'] is None:
            self.info(f"No SHODAN info found for {qry}")
            return None

        try:
            r = json.loads(res['content'])
            if "error" in r:
                self.error(f"Error returned from SHODAN: {r['error']}")
                return None
            if r.get('total', 0) == 0:
                self.info(f"No SHODAN info found for {qry}")
                return None
            return r
        except Exception as e:
            self.error(f"Error processing JSON response from SHODAN: {e}")
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

        if self.opts['api_key'] == "":
            self.error("You enabled sfp_shodan but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "DOMAIN_NAME":
            hosts = self.searchHosts(eventData)
            if hosts is None:
                return

            evt = SpiderFootEvent("RAW_RIR_DATA", str(hosts), self.__name__, event)
            self.notifyListeners(evt)

        if eventName == 'WEB_ANALYTICS_ID':
            try:
                network = eventData.split(": ")[0]
                analytics_id = eventData.split(": ")[1]
            except Exception as e:
                self.error(f"Unable to parse WEB_ANALYTICS_ID: {eventData} ({e})")
                return

            if network not in ['Google AdSense', 'Google Analytics', 'Google Site Verification']:
                self.debug(f"Skipping {eventData}, as not supported.")
                return

            rec = self.searchHtml(analytics_id)

            if rec is None:
                return

            evt = SpiderFootEvent("RAW_RIR_DATA", str(rec), self.__name__, event)
            self.notifyListeners(evt)
            return

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

            if rec.get('os') is not None:
                evt = SpiderFootEvent("OPERATING_SYSTEM", f"{rec.get('os')} ({addr})", self.__name__, pevent)
                self.notifyListeners(evt)

            if rec.get('devtype') is not None:
                evt = SpiderFootEvent("DEVICE_TYPE", f"{rec.get('devtype')} ({addr})", self.__name__, pevent)
                self.notifyListeners(evt)

            if rec.get('country_name') is not None:
                location = ', '.join([_f for _f in [rec.get('city'), rec.get('country_name')] if _f])
                evt = SpiderFootEvent("GEOINFO", location, self.__name__, pevent)
                self.notifyListeners(evt)

            if 'data' not in rec:
                continue

            self.info(f"Found SHODAN data for {eventData}")
            ports = list()
            banners = list()
            asns = list()
            products = list()
            vulnlist = list()
            for r in rec['data']:
                port = str(r.get('port'))
                banner = r.get('banner')
                asn = r.get('asn')
                product = r.get('product')
                vulns = r.get('vulns')

                if port is not None:
                    cp = addr + ":" + port
                    if cp not in ports:
                        ports.append(cp)
                        evt = SpiderFootEvent("TCP_PORT_OPEN", cp, self.__name__, pevent)
                        self.notifyListeners(evt)

                if banner is not None:
                    if banner not in banners:
                        banners.append(banner)
                        evt = SpiderFootEvent("TCP_PORT_OPEN_BANNER", banner, self.__name__, pevent)
                        self.notifyListeners(evt)

                if product is not None:
                    if product not in products:
                        products.append(product)
                        evt = SpiderFootEvent("SOFTWARE_USED", product, self.__name__, pevent)
                        self.notifyListeners(evt)

                if asn is not None:
                    if asn not in asns:
                        asns.append(asn)
                        evt = SpiderFootEvent("BGP_AS_MEMBER", asn.replace("AS", ""), self.__name__, pevent)
                        self.notifyListeners(evt)

                if vulns is not None:
                    for vuln in vulns.keys():
                        if vuln not in vulnlist:
                            vulnlist.append(vuln)
                            etype, cvetext = self.sf.cveInfo(vuln)
                            evt = SpiderFootEvent(etype, cvetext, self.__name__, pevent)
                            self.notifyListeners(evt)

# End of sfp_shodan class
