# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_alienvault
# Purpose:      Query AlienVault OTX
#
# Author:      Steve Micallef
#
# Created:     26/03/2017
# Copyright:   (c) Steve Micallef
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_alienvault(SpiderFootPlugin):

    meta = {
        'name': "AlienVault OTX",
        'summary': "Obtain information from AlienVault Open Threat Exchange (OTX)",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://otx.alienvault.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://otx.alienvault.com/faq",
                "https://otx.alienvault.com/api",
                "https://otx.alienvault.com/submissions/list",
                "https://otx.alienvault.com/pulse/create",
                "https://otx.alienvault.com/endpoint-security/welcome",
                "https://otx.alienvault.com/browse/"
            ],
            'apiKeyInstructions': [
                "Visit https://otx.alienvault.com/",
                "Sign up for a free account",
                "Navigate to https://otx.alienvault.com/settings",
                "The API key is listed under 'OTX Key'"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://otx.alienvault.com/",
            'logo': "https://otx.alienvault.com/assets/images/otx-logo.svg",
            'description': "The World’s First Truly Open Threat Intelligence Community\n"
            "Open Threat Exchange is the neighborhood watch of the global intelligence community. "
            "It enables private companies, independent security researchers, and government agencies to "
            "openly collaborate and share the latest information about emerging threats, attack methods, "
            "and malicious actors, promoting greater security across the entire community.\n"
            "OTX changed the way the intelligence community creates and consumes threat data. "
            "In OTX, anyone in the security community can contribute, discuss, research, validate, "
            "and share threat data. You can integrate community-generated OTX threat data directly "
            "into your AlienVault and third-party security products, so that your threat detection defenses "
            "are always up to date with the latest threat intelligence. "
            "Today, 100,000 participants in 140 countries contribute over 19 million threat indicators daily."
        }
    }

    # Default options
    opts = {
        "api_key": "",
        "verify": True,
        "reputation_age_limit_days": 30,
        "cohost_age_limit_days": 30,
        "threat_score_min": 2,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120,
        'subnetlookup': True,
        'maxsubnet': 24,
        'maxv6subnet': 120,
        'max_pages': 50,
        'maxcohost': 100,
        'checkaffiliates': True
    }

    # Option descriptions
    optdescs = {
        "api_key": "AlienVault OTX API Key.",
        "verify": "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        "reputation_age_limit_days": "Ignore any reputation records older than this many days. 0 = unlimited.",
        "cohost_age_limit_days": "Ignore any co-hosts older than this many days. 0 = unlimited.",
        "threat_score_min": "Minimum AlienVault threat score.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum IPv4 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6netblock': "If looking up owned netblocks, the maximum IPv6 netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'subnetlookup': "Look up all IPs on subnets which your target is a part of for blacklisting?",
        'maxsubnet': "If looking up subnets, the maximum IPv4 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6subnet': "If looking up subnets, the maximum IPv6 subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'max_pages': "Maximum number of pages of URL results to fetch.",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        'checkaffiliates': "Apply checks to affiliates?"
    }

    results = None
    errorState = False
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.cohostcount = 0
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return [
            "INTERNET_NAME",
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
            "NETBLOCK_OWNER",
            "NETBLOCKV6_OWNER",
            "NETBLOCK_MEMBER",
            "NETBLOCKV6_MEMBER",
            "NETBLOCK_OWNER",
            "NETBLOCK_MEMBER",
        ]

    # What events this module produces
    def producedEvents(self):
        return [
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "AFFILIATE_IPADDR",
            "AFFILIATE_IPV6_ADDRESS",
            "CO_HOSTED_SITE",
            "INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "MALICIOUS_IPADDR",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "LINKED_URL_INTERNAL"
        ]

    # Parse API response
    def parseAPIResponse(self, res):
        # Future proofing - AlienVault OTX does not implement rate limiting
        if res['code'] == '429':
            self.error("You are being rate-limited by AienVault OTX")
            self.errorState = True
            return None

        if res['code'] == "403":
            self.error("AlienVault OTX API key seems to have been rejected or you have exceeded usage limits for the month.")
            self.errorState = True
            return None

        if res['content'] is None or res['code'] == "404":
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from AlienVault OTX: {e}")

        return None

    def queryReputation(self, qry):
        if ":" in qry:
            target_type = "IPv6"
        elif self.sf.validIP(qry):
            target_type = "IPv4"
        else:
            self.info(f"Could not determine target type for {qry}")
            return None

        headers = {
            'Accept': 'application/json',
            'X-OTX-API-KEY': self.opts['api_key']
        }

        res = self.sf.fetchUrl(
            f"https://otx.alienvault.com/api/v1/indicators/{target_type}/{qry}/reputation",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers)

        return self.parseAPIResponse(res)

    def queryPassiveDns(self, qry):
        if ":" in qry:
            target_type = "IPv6"
        elif self.sf.validIP(qry):
            target_type = "IPv4"
        else:
            self.info(f"Could not determine target type for {qry}")
            return None

        headers = {
            'Accept': 'application/json',
            'X-OTX-API-KEY': self.opts['api_key']
        }

        res = self.sf.fetchUrl(
            f"https://otx.alienvault.com/api/v1/indicators/{target_type}/{qry}/passive_dns",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers)

        return self.parseAPIResponse(res)

    def queryDomainUrlList(self, qry, page=1, per_page=50):
        params = urllib.parse.urlencode({
            'page': page,
            'limit': per_page
        })

        headers = {
            'Accept': 'application/json',
            'X-OTX-API-KEY': self.opts['api_key']
        }
        res = self.sf.fetchUrl(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{qry}/url_list?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers)

        return self.parseAPIResponse(res)

    def queryHostnameUrlList(self, qry, page=1, per_page=50):
        params = urllib.parse.urlencode({
            'page': page,
            'limit': per_page
        })

        headers = {
            'Accept': 'application/json',
            'X-OTX-API-KEY': self.opts['api_key']
        }
        res = self.sf.fetchUrl(
            f"https://otx.alienvault.com/api/v1/indicators/hostname/{qry}/url_list?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot",
            headers=headers)

        return self.parseAPIResponse(res)

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts['api_key'] == "":
            self.error(f"You enabled {self.__class__.__name__} but did not set an API key!")
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
            return

        if eventName == 'INTERNET_NAME':
            urls = list()
            page = 1
            while page <= self.opts['max_pages']:
                if self.checkForStop():
                    break
                if self.errorState:
                    break

                data = self.queryHostnameUrlList(eventData, page=page)
                page += 1

                url_list = data.get('url_list')
                if not url_list:
                    break

                for url in url_list:
                    u = url.get('url')
                    if not u:
                        continue
                    urls.append(u)

                if not data.get('has_next'):
                    break

            if self.sf.isDomain(eventData, self.opts['_internettlds']):
                page = 1
                while page <= self.opts['max_pages']:
                    if self.checkForStop():
                        break
                    if self.errorState:
                        break

                    data = self.queryDomainUrlList(eventData, page=page)
                    page += 1

                    url_list = data.get('url_list')
                    if not url_list:
                        break

                    for url in url_list:
                        u = url.get('url')
                        if not u:
                            continue
                        urls.append(u)

                    if not data.get('has_next'):
                        break

            for url in set(urls):
                if not url:
                    continue

                host = self.sf.urlFQDN(url.lower())

                if not self.getTarget().matches(host, includeChildren=True, includeParents=True):
                    continue

                if url not in self.results:
                    self.results[url] = True
                    evt = SpiderFootEvent('LINKED_URL_INTERNAL', url, self.__name__, event)
                    self.notifyListeners(evt)

            return

        if eventName in ['NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            if not self.opts['netblocklookup']:
                return

            if eventName == 'NETBLOCKV6_OWNER':
                max_netblock = self.opts['maxv6netblock']
            else:
                max_netblock = self.opts['maxnetblock']

            max_netblock = self.opts['maxnetblock']
            if IPNetwork(eventData).prefixlen < max_netblock:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_netblock}")
                return

        if eventName in ['NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            if not self.opts['subnetlookup']:
                return

            if eventName == 'NETBLOCKV6_MEMBER':
                max_subnet = self.opts['maxv6subnet']
            else:
                max_subnet = self.opts['maxsubnet']

            if IPNetwork(eventData).prefixlen < max_subnet:
                self.debug(f"Network size bigger than permitted: {IPNetwork(eventData).prefixlen} > {max_subnet}")
                return

        qrylist = list()
        if eventName.startswith("NETBLOCK"):
            for ipaddr in IPNetwork(eventData):
                qrylist.append(str(ipaddr))
                self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)

        # For IP addresses, do the additional passive DNS lookup
        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS']:
            ret = self.queryPassiveDns(eventData)

            if ret is None:
                self.info(f"No Passive DNS info for {eventData}")
            else:
                passive_dns = ret.get('passive_dns')
                if passive_dns:
                    self.debug(f"Found passive DNS results for {eventData} in AlienVault OTX")
                    for rec in passive_dns:
                        host = rec.get('hostname')

                        if not host:
                            continue

                        if self.getTarget().matches(host, includeParents=True):
                            evtType = "INTERNET_NAME"
                            if not self.sf.resolveHost(host) and not self.sf.resolveHost6(host):
                                evtType = "INTERNET_NAME_UNRESOVLED"
                            evt = SpiderFootEvent(evtType, host, self.__name__, event)
                            self.notifyListeners(evt)
                            continue

                        if self.opts['cohost_age_limit_days'] > 0:
                            try:
                                last = rec.get("last", "")
                                last_dt = datetime.strptime(last, '%Y-%m-%dT%H:%M:%S')
                                last_ts = int(time.mktime(last_dt.timetuple()))
                                age_limit_ts = int(time.time()) - (86400 * self.opts['cohost_age_limit_days'])
                                if last_ts < age_limit_ts:
                                    self.debug(f"Passive DNS record {host} found for {eventData} is too old ({last_dt}), skipping.")
                                    continue
                            except Exception:
                                self.info("Could not parse date from AlienVault data, so ignoring cohost_age_limit_days")

                        if self.opts["verify"] and not self.sf.validateIP(host, eventData):
                            self.debug(f"Co-host {host} no longer resolves to {eventData}, skipping")
                            continue

                        if self.cohostcount < self.opts['maxcohost']:
                            e = SpiderFootEvent("CO_HOSTED_SITE", host, self.__name__, event)
                            self.notifyListeners(e)
                            self.cohostcount += 1
                        else:
                            self.info(f"Maximum co-host threshold exceeded ({self.opts['maxcohost']}), ignoring co-host {host}")

        if eventName in ['IP_ADDRESS', 'IPV6_ADDRESS', 'NETBLOCK_OWNER', 'NETBLOCKV6_OWNER']:
            evtType = 'MALICIOUS_IPADDR'
        elif eventName in ['AFFILIATE_IPADDR', 'AFFILIATE_IPV6_ADDRESS', 'NETBLOCK_MEMBER', 'NETBLOCKV6_MEMBER']:
            evtType = 'MALICIOUS_AFFILIATE_IPADDR'
        elif eventName == "INTERNET_NAME":
            evtType = 'MALICIOUS_INTERNET_NAME'
        else:
            self.debug(f"Unexpected event type {eventName}, skipping")
            return

        for addr in qrylist:
            if self.checkForStop():
                return
            if self.errorState:
                return

            rec = self.queryReputation(addr)

            if not rec:
                continue

            if rec.get("reputation", None):
                self.debug(f"Found reputation info for {addr} in AlienVault OTX")
                rec_history = rec['reputation'].get("activities", list())
                threat_score = rec['reputation']['threat_score']
                threat_score_min = self.opts['threat_score_min']

                if threat_score < threat_score_min:
                    self.debug(f"Threat score {threat_score} smaller than {threat_score_min}, skipping.")
                    continue

                descr = f"AlienVault Threat Score: {threat_score}"

                for result in rec_history:
                    nm = result.get("name", None)

                    if nm is None or nm in descr:
                        continue

                    descr += "\n - " + nm
                    created = result.get("last_date", "")
                    if self.opts['reputation_age_limit_days'] > 0:
                        try:
                            # 2014-11-06T10:45:00.000
                            created_dt = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S')
                            created_ts = int(time.mktime(created_dt.timetuple()))
                            age_limit_ts = int(time.time()) - (86400 * self.opts['reputation_age_limit_days'])
                            if created_ts < age_limit_ts:
                                self.debug(f"Reputation record found for {addr} is too old ({created_dt}), skipping.")
                                continue
                        except Exception:
                            self.info("Could not parse date from AlienVault data, so ignoring reputation_age_limit_days")

                # For netblocks, we need to create the IP address event so that
                # the threat intel event is more meaningful.
                if eventName == 'NETBLOCK_OWNER':
                    pevent = SpiderFootEvent("IP_ADDRESS", addr, self.__name__, event)
                    self.notifyListeners(pevent)
                if eventName == 'NETBLOCKV6_OWNER':
                    pevent = SpiderFootEvent("IPV6_ADDRESS", addr, self.__name__, event)
                    self.notifyListeners(pevent)
                elif eventName == 'NETBLOCK_MEMBER':
                    pevent = SpiderFootEvent("AFFILIATE_IPADDR", addr, self.__name__, event)
                    self.notifyListeners(pevent)
                elif eventName == 'NETBLOCKV6_MEMBER':
                    pevent = SpiderFootEvent("AFFILIATE_IPV6_ADDRESS", addr, self.__name__, event)
                    self.notifyListeners(pevent)
                else:
                    pevent = event

                e = SpiderFootEvent(evtType, descr, self.__name__, pevent)
                self.notifyListeners(e)

# End of sfp_alienvault class
