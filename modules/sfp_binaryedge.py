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
import socket
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent

class sfp_binaryedge(SpiderFootPlugin):
    """BinaryEdge:Footprint,Investigate,Passive:Search Engines:apikey:Obtain information from BinaryEdge.io's Internet scanning systems about breaches, vulerabilities, torrents and passive DNS."""


    # Default options
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

    # Option descriptions
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

    # Be sure to completely clear any class variables in setup()
    # or you run the risk of data persisting between scan runs.

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

        # Clear / reset any other class member variables here
        # or you risk them persisting between threads.

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "DOMAIN_NAME", "EMAILADDR", 
                "NETBLOCK_OWNER", "NETBLOCK_MEMBER" ]

    # What events this module produces
    def producedEvents(self):
        return ["INTERNET_NAME", "VULNERABILITY", "TCP_PORT_OPEN",
                "TCP_PORT_OPEN_BANNER", "EMAILADDR_COMPROMISED", 
                "UDP_PORT_OPEN", "UDP_PORT_OPEN_INFO",
                "CO_HOSTED_SITE", "MALICIOUS_IPADDR"]

    # Verify a host resolves
    def resolveHost(self, host):
        try:
            # IDNA-encode the hostname in case it contains unicode
            if type(host) != unicode:
                host = unicode(host, "utf-8", errors='replace').encode("idna")
            else:
                host = host.encode("idna")

            addrs = socket.gethostbyname_ex(host)
            return True
        except BaseException as e:
            self.sf.debug("Unable to resolve " + host + ": " + str(e))
            return False

    def query(self, qry, querytype, page=1):
        ret = None
        retarr = list()

        if self.errorState:
            return None

        if querytype == "email":
            queryurl = "/v2/query/dataleaks/email/{0}?page={1}"
        if querytype == "ports":
            queryurl = "/v2/query/ip/{0}?page={1}"
        if querytype == "torrent":
            queryurl = "/v2/query/torrent/historical/{0}?page={1}"
        if querytype == "vuln":
            queryurl = "/v2/query/cve/ip/{0}?page={1}"
        if querytype == "subs":
            queryurl = "/v2/query/domains/subdomain/{0}?page={1}"
        if querytype == "passive":
            queryurl = "/v2/query/domains/ip/{0}?page={1}"
        
        binaryedgeurl = "https://api.binaryedge.io"
        headers = {
            'X-Key': self.opts['binaryedge_api_key']
        }
        url = binaryedgeurl + queryurl.format(qry.encode('utf-8', errors='replace'), page)
        res = self.sf.fetchUrl(url, timeout=self.opts['_fetchtimeout'], 
                               useragent="SpiderFoot", headers=headers)

        if res['code'] in [ "429", "500" ]:
            self.sf.error("BinaryEdge.io API key seems to have been rejected or you have exceeded usage limits for the month.", False)
            self.errorState = True
            return None

        if res['content'] is None:
            self.sf.info("No BinaryEdge.io info found for " + qry)
            return None

        if len(res['content']) == 0:
            self.sf.info("No BinaryEdge.io info found for " + qry)
            return None

        try:
            info = json.loads(res['content'])
        except Exception as e:
            self.sf.error("Error processing JSON response from BinaryEdge.io.", False)
            return None

        if info.get('page') and info['total'] > info.get('pagesize', 100) * info.get('page', 0):
            page = info['page'] + 1
            if page > self.opts['maxpages']:
                self.sf.error("Maximum number of pages reached.", False)
                return [info]
            retarr.append(info)
            e = self.query(qry, querytype, page)
            if e:
                retarr.extend(e)
        else:
            retarr.append(info)

        return retarr

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return None

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if self.opts['binaryedge_api_key'] == "":
            self.sf.error("You enabled sfp_binaryedge but did not set an API key!", False)
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

        # For IP Addresses, do the additional passive DNS lookup
        if eventName == "IP_ADDRESS":
            evtType = "CO_HOSTED_SITE"
            ret = self.query(eventData, "passive")
            if ret is None:
                self.sf.info("No Passive DNS info for " + eventData)
                return None

            for rec in ret:
                if "events" not in rec:
                    continue

                self.sf.debug("Found passive DNS results in BinaryEdge.io")
                res = rec["events"]
                for rec in res:
                    host = rec['domain']
                    if host == eventData:
                        continue
                    if self.getTarget().matches(host, includeParents=True):
                        if self.opts['verify']:
                            if not self.resolveHost(host):
                                continue
                        evt = SpiderFootEvent("INTERNET_NAME", host, self.__name__, event)
                        self.notifyListeners(evt)
                        self.reportedhosts[host] = True
                        continue

                    if self.cohostcount < self.opts['maxcohost']:
                        e = SpiderFootEvent(evtType, host, self.__name__, event)
                        self.notifyListeners(e)
                        self.cohostcount += 1

        if eventName == "EMAILADDR":
            evtType = "EMAILADDR_COMPROMISED"
            ret = self.query(eventData, "email")
            if ret is None:
                self.sf.info("No leak info for " + eventData)
                return None

            for rec in ret:
                if "events" not in rec:
                    continue

                self.sf.debug("Found compromised account results in BinaryEdge.io")
                res = rec["events"]
                for rec in res:
                    e = SpiderFootEvent(evtType, rec, self.__name__, event)
                    self.notifyListeners(e)

        if eventName == "DOMAIN_NAME":
            evtType = "INTERNET_NAME"
            ret = self.query(eventData, "subs")
            if ret is None:
                self.sf.info("No hosts found for " + eventData)
                return None

            for rec in ret:
                if "events" not in rec:
                    continue

                self.sf.debug("Found host results in BinaryEdge.io")
                res = rec["events"]
                for rec in res:
                    if rec in self.reportedhosts:
                        continue
                    else:
                        self.reportedhosts[rec] = True
                    if self.opts['verify']:
                        if not self.resolveHost(rec):
                            self.sf.debug("Couldn't resolve " + rec + ", so skipping.")
                            continue
                    e = SpiderFootEvent(evtType, rec, self.__name__, event)
                    self.notifyListeners(e)

        for addr in qrylist:
            if self.checkForStop():
                return None

            if addr in self.checkedips:
                continue

            evtType = "MALICIOUS_IPADDR"
            ret = self.query(eventData, "torrent")
            if ret is None:
                self.sf.info("No torrent info for " + eventData)
                return None

            for rec in ret:
                if "events" not in rec:
                    continue

                self.sf.debug("Found torrent results in BinaryEdge.io")
                res = rec["events"]
                for rec in res:
                    created_ts = rec['origin'].get('ts') / 1000
                    age_limit_ts = int(time.time()) - (86400 * self.opts['torrent_age_limit_days'])
                    if self.opts['torrent_age_limit_days'] > 0 and created_ts < age_limit_ts:
                        self.sf.debug("Record found but too old, skipping.")
                        continue
                    dat = "Torrent: " + rec.get("torrent", "???").get("name") + " @ " + rec.get('torrent').get("source", "???")
                    e = SpiderFootEvent(evtType, dat, self.__name__, event)
                    self.notifyListeners(e)

        for addr in qrylist:
            if self.checkForStop():
                return None

            if addr in self.checkedips:
                continue

            evtType = "VULNERABILITY"
            ret = self.query(eventData, "vuln")
            if ret is None:
                self.sf.info("No vulnerability info for " + eventData)
                return None

            for rec in ret:
                if "events" not in rec:
                    continue
                if "results" not in rec['events']:
                    continue

                self.sf.debug("Found vulnerability results in BinaryEdge.io")
                res = rec["events"]["results"]
                for rec in res:
                    created_ts = rec.get('ts') / 1000
                    age_limit_ts = int(time.time()) - (86400 * self.opts['cve_age_limit_days'])
                    if self.opts['cve_age_limit_days'] > 0 and created_ts < age_limit_ts:
                        self.sf.debug("Record found but too old, skipping.")
                        continue
                    for c in rec['cves']:
                        cve = c['cve']
                        e = SpiderFootEvent(evtType, cve, self.__name__, event)
                        self.notifyListeners(e)

        for addr in qrylist:
            if self.checkForStop():
                return None

            if addr in self.checkedips:
                continue

            ret = self.query(eventData, "ports")
            if ret is None:
                self.sf.info("No port/banner info for " + eventData)
                return None

            for rec in ret:
                if "events" not in rec:
                    continue

                self.sf.debug("Found port/banner results in BinaryEdge.io")
                allres = rec["events"]
                ports = list()
                for res in allres:
                    for prec in res['results']:
                        created_ts = prec['origin'].get('ts') / 1000
                        age_limit_ts = int(time.time()) - (86400 * self.opts['port_age_limit_days'])
                        if self.opts['port_age_limit_days'] > 0 and created_ts < age_limit_ts:
                            self.sf.debug("Record found but too old, skipping.")
                            continue

                        entity = prec['target']['ip'] + ":" + str(prec['target']['port'])
                        evttype = "TCP_PORT_OPEN"
                        evtbtype = "TCP_PORT_OPEN_BANNER"
                        if prec['target']['protocol'] == "udp":
                            evttype = "UDP_PORT_OPEN"
                            evtbtype = "UDP_PORT_OPEN_INFO"

                        if not evttype+":"+str(prec['target']['port']) in ports:
                            ev = SpiderFootEvent(evttype, entity, self.__name__, event)
                            self.notifyListeners(ev)
                            ports.append(evttype+":"+str(prec['target']['port']))

                        try:
                            banner = prec['result']['data']['service']['banner']
                            e = SpiderFootEvent(evtbtype, banner, self.__name__, ev)
                            self.notifyListeners(e)
                        except BaseException as e:
                            self.sf.debug("No banner information found.")

        for addr in qrylist:
            self.checkedips[addr] = True

# End of sfp_binaryedge class
