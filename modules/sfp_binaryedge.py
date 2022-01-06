# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_binaryedge
# Purpose:      Query binaryedge.io using their API
#
# Author:      Steve Micallef
#
# Created:     02/04/2019
# Copyright:   (c) Steve Micallef 2019
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_binaryedge(SpiderFootPlugin):

    meta = {
        'name': "BinaryEdge",
        'summary': "Obtain information from BinaryEdge.io Internet scanning systems, including breaches, vulnerabilities, torrents and passive DNS.",
        'flags': ["apikey"],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Search Engines"],
        'dataSource': {
            'website': "https://www.binaryedge.io/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://docs.binaryedge.io/",
                "https://www.binaryedge.io/data.html"
            ],
            'apiKeyInstructions': [
                "Visit https://www.binaryedge.io/pricing.html",
                "Select a plan",
                "Sign up with new account",
                "Go to Account",
                "The API key is listed under 'API Access'"
            ],
            'favIcon': "https://www.binaryedge.io/img/favicon/favicon-32x32.png",
            'logo': "https://www.binaryedge.io/img/logo.png",
            'description': "We scan the entire public internet, create real-time threat intelligence streams, "
            "and reports that show the exposure of what is connected to the Internet.\n"
            "We have built a distributed platform of scanners and honeypots, to acquire, classify and correlate different types of data.\n"
            "We use all of these datapoints to match those digital assets to an organization, "
            "allowing us to provide a global, up-to-date, view of organizations known and unknown assets.",
        }
    }

    opts = {
        'binaryedge_api_key': "",
        'torrent_age_limit_days': 30,
        'cve_age_limit_days': 30,
        'port_age_limit_days': 90,
        'maxpages': 10,
        'verify': True,
        'netblocklookup': False,
        'maxnetblock': 24,
        'subnetlookup': False,
        'maxsubnet': 24,
        'maxcohost': 100
    }

    optdescs = {
        'binaryedge_api_key': "BinaryEdge.io API Key.",
        'torrent_age_limit_days': "Ignore any torrent records older than this many days. 0 = unlimited.",
        'cve_age_limit_days': "Ignore any vulnerability records older than this many days. 0 = unlimited.",
        'port_age_limit_days': "Ignore any discovered open ports/banners older than this many days. 0 = unlimited.",
        'verify': 'Verify that any hostnames found on the target domain still resolve?',
        'maxpages': "Maximum number of pages to iterate through, to avoid exceeding BinaryEdge API usage limits. APIv2 has a maximum of 500 pages (10,000 results).",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of?",
        'maxsubnet': "If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting."
    }

    results = None
    errorState = False
    cohostcount = 0
    reportedhosts = None
    checkedips = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.reportedhosts = self.tempStorage()
        self.checkedips = self.tempStorage()
        self.cohostcount = 0
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "DOMAIN_NAME",
            "EMAILADDR",
            "NETBLOCK_OWNER",
            "NETBLOCK_MEMBER"
        ]

    def producedEvents(self):
        return [
            "INTERNET_NAME",
            "DOMAIN_NAME",
            "VULNERABILITY_CVE_CRITICAL",
            "VULNERABILITY_CVE_HIGH",
            "VULNERABILITY_CVE_MEDIUM",
            "VULNERABILITY_CVE_LOW",
            "VULNERABILITY_GENERAL",
            "TCP_PORT_OPEN",
            "TCP_PORT_OPEN_BANNER",
            "EMAILADDR_COMPROMISED",
            "UDP_PORT_OPEN",
            "UDP_PORT_OPEN_INFO",
            "CO_HOSTED_SITE",
            "MALICIOUS_IPADDR"
        ]

    def query(self, qry, querytype, page=1):
        retarr = list()

        if self.errorState:
            return None

        if querytype == "email":
            queryurl = "dataleaks/email"
        elif querytype == "ip":
            queryurl = "ip"
        elif querytype == "torrent":
            queryurl = "torrent/historical"
        elif querytype == "vuln":
            queryurl = "cve/ip"
        elif querytype == "subs":
            queryurl = "domains/subdomain"
        elif querytype == "passive":
            queryurl = "domains/ip"
        else:
            self.error(f"Invalid query type: {querytype}")
            return None

        headers = {
            'X-Key': self.opts['binaryedge_api_key']
        }

        res = self.sf.fetchUrl(
            f"https://api.binaryedge.io/v2/query/{queryurl}/{qry}?page={page}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers
        )

        if res['code'] in ["429", "500"]:
            self.error("BinaryEdge.io API key seems to have been rejected or you have exceeded usage limits for the month.")
            self.errorState = True
            return None

        if not res['content']:
            self.info(f"No BinaryEdge.io info found for {qry}")
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from BinaryEdge.io: {e}")
            return None

        if info.get('page') and info['total'] > info.get('pagesize', 100) * info.get('page', 0):
            page = info['page'] + 1
            if page > self.opts['maxpages']:
                self.error("Maximum number of pages reached.")
                return [info]
            retarr.append(info)
            e = self.query(qry, querytype, page)
            if e:
                retarr.extend(e)
        else:
            retarr.append(info)

        return retarr

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["binaryedge_api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName == "EMAILADDR":
            ret = self.query(eventData, "email")
            if ret is None:
                self.info(f"No leak info for {eventData}")
                return

            for rec in ret:
                events = rec.get('events')
                if not events:
                    continue

                self.debug("Found compromised account results in BinaryEdge.io")

                for leak in events:
                    e = SpiderFootEvent('EMAILADDR_COMPROMISED', f"{eventData} [{leak}]", self.__name__, event)
                    self.notifyListeners(e)

            # No further API endpoints available for email addresses. we can bail out here
            return

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            net_size = IPNetwork(eventData).prefixlen
            max_netblock = self.opts['maxnetblock']
            if net_size < max_netblock:
                self.debug(f"Network size bigger than permitted: {net_size} > {max_netblock}")
                return

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return

            net_size = IPNetwork(eventData).prefixlen
            max_subnet = self.opts['maxsubnet']
            if net_size < max_subnet:
                self.debug(f"Network size bigger than permitted: {net_size} > {max_subnet}")
                return

        # For IP Addresses, do the additional passive DNS lookup
        if eventName == "IP_ADDRESS":
            evtType = "CO_HOSTED_SITE"
            ret = self.query(eventData, "passive")
            if ret is None:
                self.info(f"No Passive DNS info for {eventData}")
                return

            for rec in ret:
                events = rec.get('events')
                if not events:
                    continue

                self.debug("Found passive DNS results in BinaryEdge.io")
                for rec in events:
                    host = rec['domain']
                    if host == eventData:
                        continue

                    if self.getTarget().matches(host, includeParents=True):
                        if self.opts['verify']:
                            if not self.sf.resolveHost(host) and not self.sf.resolveHost6(host):
                                continue

                        evt = SpiderFootEvent("INTERNET_NAME", host, self.__name__, event)
                        self.notifyListeners(evt)
                        if self.sf.isDomain(host, self.opts['_internettlds']):
                            evt = SpiderFootEvent("DOMAIN_NAME", host, self.__name__, event)
                            self.notifyListeners(evt)

                        self.reportedhosts[host] = True
                        continue

                    if self.cohostcount < self.opts['maxcohost']:
                        e = SpiderFootEvent(evtType, host, self.__name__, event)
                        self.notifyListeners(e)
                        self.cohostcount += 1

        if eventName == "DOMAIN_NAME":
            ret = self.query(eventData, "subs")
            if ret is None:
                self.info(f"No hosts found for {eventData}")
                return

            for rec in ret:
                events = rec.get('events')
                if not events:
                    continue

                self.debug("Found host results in BinaryEdge.io")
                for rec in events:
                    if rec in self.reportedhosts:
                        continue

                    self.reportedhosts[rec] = True

                    if self.opts['verify']:
                        if not self.sf.resolveHost(rec) and not self.sf.resolveHost6(rec):
                            self.debug(f"Couldn't resolve {rec}, so skipping.")
                            continue

                    e = SpiderFootEvent('INTERNET_NAME', rec, self.__name__, event)
                    self.notifyListeners(e)

        # Loop through all IP addresses / host names
        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        for addr in qrylist:
            if self.checkForStop():
                return

            if self.errorState:
                return

            if addr in self.checkedips:
                continue

            ret = self.query(addr, "torrent")
            if ret is None:
                self.info(f"No torrent info for {addr}")
                continue

            for rec in ret:
                events = rec.get('events')
                if not events:
                    continue

                self.debug(f"Found torrent results for {addr} in BinaryEdge.io")

                for rec in events:
                    created_ts = rec['origin'].get('ts') / 1000
                    age_limit_ts = int(time.time()) - (86400 * self.opts['torrent_age_limit_days'])

                    if self.opts['torrent_age_limit_days'] > 0 and created_ts < age_limit_ts:
                        self.debug("Record found but too old, skipping.")
                        continue

                    dat = "Torrent: " + rec.get("torrent", "???").get("name") + " @ " + rec.get('torrent').get("source", "???")
                    e = SpiderFootEvent('MALICIOUS_IPADDR', dat, self.__name__, event)
                    self.notifyListeners(e)

        for addr in qrylist:
            if self.checkForStop():
                return

            if self.errorState:
                return

            if addr in self.checkedips:
                continue

            ret = self.query(addr, "vuln")
            if ret is None:
                self.info(f"No vulnerability info for {addr}")
                continue

            for rec in ret:
                events = rec.get('events')
                if not events:
                    continue

                results = events.get('results')
                if not results:
                    continue

                self.debug("Found vulnerability results in BinaryEdge.io")
                for rec in results:
                    created_ts = rec.get('ts') / 1000
                    age_limit_ts = int(time.time()) - (86400 * self.opts['cve_age_limit_days'])

                    if self.opts['cve_age_limit_days'] > 0 and created_ts < age_limit_ts:
                        self.debug("Record found but too old, skipping.")
                        continue

                    cves = rec.get('cves')
                    if cves:
                        for c in cves:
                            etype, cvetext = self.sf.cveInfo(c['cve'])
                            e = SpiderFootEvent(etype, cvetext, self.__name__, event)
                            self.notifyListeners(e)

        for addr in qrylist:
            if self.checkForStop():
                return

            if self.errorState:
                return

            if addr in self.checkedips:
                continue

            ret = self.query(addr, "ip")
            if ret is None:
                self.info(f"No port/banner info for {addr}")
                return

            for rec in ret:
                events = rec.get('events')
                if not events:
                    continue

                self.debug("Found port/banner results in BinaryEdge.io")

                ports = list()
                for res in events:
                    for prec in res['results']:
                        created_ts = prec['origin'].get('ts') / 1000
                        age_limit_ts = int(time.time()) - (86400 * self.opts['port_age_limit_days'])

                        if self.opts['port_age_limit_days'] > 0 and created_ts < age_limit_ts:
                            self.debug("Record found but too old, skipping.")
                            continue

                        port = str(prec['target']['port'])
                        entity = prec['target']['ip'] + ":" + port
                        evttype = "TCP_PORT_OPEN"
                        evtbtype = "TCP_PORT_OPEN_BANNER"

                        if prec['target']['protocol'] == "udp":
                            evttype = "UDP_PORT_OPEN"
                            evtbtype = "UDP_PORT_OPEN_INFO"

                        if f"{evttype}:{port}" not in ports:
                            ev = SpiderFootEvent(evttype, entity, self.__name__, event)
                            self.notifyListeners(ev)
                            ports.append(f"{evttype}:{port}")

                        try:
                            banner = prec['result']['data']['service']['banner']
                            if '\\r\\n\\r\\n' in banner and "HTTP/" in banner:
                                # We don't want the content after HTTP banners
                                banner = banner.split('\\r\\n\\r\\n')[0]
                                banner = banner.replace("\\r\\n", "\n")
                        except Exception:
                            self.debug("No banner information found.")
                            continue

                        e = SpiderFootEvent(evtbtype, banner, self.__name__, ev)
                        self.notifyListeners(e)

        for addr in qrylist:
            self.checkedips[addr] = True

# End of sfp_binaryedge class
