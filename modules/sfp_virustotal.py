# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_virustotal
# Purpose:      Query VirusTotal for identified IP addresses.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     21/03/2014
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


class sfp_virustotal(SpiderFootPlugin):

    meta = {
        'name': "VirusTotal",
        'summary': "Obtain information from VirusTotal about identified IP addresses.",
        'flags': ["apikey"],
        'useCases': ["Investigate", "Passive"],
        'categories': ["Reputation Systems"],
        'dataSource': {
            'website': "https://www.virustotal.com/",
            'model': "FREE_AUTH_LIMITED",
            'references': [
                "https://developers.virustotal.com/reference"
            ],
            'apiKeyInstructions': [
                "Visit https://www.virustotal.com/",
                "Register a free account",
                "Click on your profile",
                "Click on API Key",
                "The API key is listed under 'API Key'"
            ],
            'favIcon': "https://www.virustotal.com/gui/images/favicon.png",
            'logo': "https://www.virustotal.com/gui/images/logo.svg",
            'description': "Analyze suspicious files and URLs to detect types of malware, "
            "automatically share them with the security community.",
        }
    }

    opts = {
        'api_key': '',
        'verify': True,
        'publicapi': True,
        'checkcohosts': True,
        'checkaffiliates': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'subnetlookup': True,
        'maxsubnet': 24
    }

    optdescs = {
        'api_key': 'VirusTotal API Key.',
        'publicapi': 'Are you using a public key? If so SpiderFoot will pause for 15 seconds after each query to avoid VirusTotal dropping requests.',
        'checkcohosts': 'Check co-hosted sites?',
        'checkaffiliates': 'Check affiliates?',
        'netblocklookup': 'Look up all IPs on netblocks deemed to be owned by your target for possible hosts on the same target subdomain/domain?',
        'maxnetblock': 'If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
        'subnetlookup': 'Look up all IPs on subnets which your target is a part of?',
        'maxsubnet': 'If looking up subnets, the maximum subnet size to look up all the IPs within (CIDR value, 24 = /24, 16 = /16, etc.)',
        'verify': 'Verify that any hostnames found on the target domain still resolve?'
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "AFFILIATE_IPADDR",
            "INTERNET_NAME",
            "CO_HOSTED_SITE",
            "NETBLOCK_OWNER",
            "NETBLOCK_MEMBER"
        ]

    def producedEvents(self):
        return [
            "MALICIOUS_IPADDR",
            "MALICIOUS_INTERNET_NAME",
            "MALICIOUS_COHOST",
            "MALICIOUS_AFFILIATE_INTERNET_NAME",
            "MALICIOUS_AFFILIATE_IPADDR",
            "MALICIOUS_NETBLOCK",
            "MALICIOUS_SUBNET",
            "INTERNET_NAME",
            "AFFILIATE_INTERNET_NAME",
            "INTERNET_NAME_UNRESOLVED",
            "DOMAIN_NAME"
        ]

    def queryIp(self, qry):
        params = urllib.parse.urlencode({
            'ip': qry,
            'apikey': self.opts['api_key'],
        })

        res = self.sf.fetchUrl(
            f"https://www.virustotal.com/vtapi/v2/ip-address/report?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )

        # Public API is limited to 4 queries per minute
        if self.opts['publicapi']:
            time.sleep(15)

        if res['content'] is None:
            self.info(f"No VirusTotal info found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from VirusTotal: {e}")
            self.errorState = True

        return None

    def queryDomain(self, qry):
        params = urllib.parse.urlencode({
            'domain': qry,
            'apikey': self.opts['api_key'],
        })

        res = self.sf.fetchUrl(
            f"https://www.virustotal.com/vtapi/v2/domain/report?{params}",
            timeout=self.opts['_fetchtimeout'],
            useragent="SpiderFoot"
        )

        if res['code'] == "204":
            self.error("Your request to VirusTotal was throttled.")
            return None

        # Public API is limited to 4 queries per minute
        if self.opts['publicapi']:
            time.sleep(15)

        if res['content'] is None:
            self.info(f"No VirusTotal info found for {qry}")
            return None

        try:
            return json.loads(res['content'])
        except Exception as e:
            self.error(f"Error processing JSON response from VirusTotal: {e}")
            self.errorState = True

        return None

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.opts["api_key"] == "":
            self.error(
                f"You enabled {self.__class__.__name__} but did not set an API key!"
            )
            self.errorState = True
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        if eventName.startswith("AFFILIATE") and not self.opts['checkaffiliates']:
            return

        if eventName == 'CO_HOSTED_SITE' and not self.opts['checkcohosts']:
            return

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            net_size = IPNetwork(eventData).prefixlen
            max_netblock = self.opts['maxnetblock']
            if net_size < max_netblock:
                self.debug(f"Network size {net_size} bigger than permitted: {max_netblock}")
                return

        if eventName == 'NETBLOCK_MEMBER':
            if not self.opts['subnetlookup']:
                return

            net_size = IPNetwork(eventData).prefixlen
            max_subnet = self.opts['maxsubnet']
            if net_size < max_subnet:
                self.debug(f"Network size {net_size} bigger than permitted: {max_subnet}")
                return

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

            if self.sf.validIP(addr):
                info = self.queryIp(addr)
            else:
                info = self.queryDomain(addr)

            if info is None:
                continue

            if len(info.get('detected_urls', [])) > 0:
                self.info(f"Found VirusTotal URL data for {addr}")

                if eventName in ["IP_ADDRESS"] or eventName.startswith("NETBLOCK_"):
                    evt = "MALICIOUS_IPADDR"
                    infotype = "ip-address"

                if eventName == "AFFILIATE_IPADDR":
                    evt = "MALICIOUS_AFFILIATE_IPADDR"
                    infotype = "ip-address"

                if eventName == "INTERNET_NAME":
                    evt = "MALICIOUS_INTERNET_NAME"
                    infotype = "domain"

                if eventName == "AFFILIATE_INTERNET_NAME":
                    evt = "MALICIOUS_AFFILIATE_INTERNET_NAME"
                    infotype = "domain"

                if eventName == "CO_HOSTED_SITE":
                    evt = "MALICIOUS_COHOST"
                    infotype = "domain"

                infourl = f"<SFURL>https://www.virustotal.com/en/{infotype}/{addr}/information/</SFURL>"

                e = SpiderFootEvent(
                    evt, f"VirusTotal [{addr}]\n{infourl}",
                    self.__name__,
                    event
                )
                self.notifyListeners(e)

            domains = list()

            # Treat siblings as affiliates if they are of the original target, otherwise
            # they are additional hosts within the target.
            if 'domain_siblings' in info:
                if eventName in ["IP_ADDRESS", "INTERNET_NAME"]:
                    for domain in info['domain_siblings']:
                        domains.append(domain)

            if 'subdomains' in info:
                if eventName == "INTERNET_NAME":
                    for domain in info['subdomains']:
                        domains.append(domain)

            for domain in set(domains):
                if domain in self.results:
                    continue

                if self.getTarget().matches(domain):
                    evt_type = 'INTERNET_NAME'
                else:
                    evt_type = 'AFFILIATE_INTERNET_NAME'

                if self.opts['verify'] and not self.sf.resolveHost(domain) and not self.sf.resolveHost6(domain):
                    self.debug(f"Host {domain} could not be resolved")
                    evt_type += '_UNRESOLVED'

                evt = SpiderFootEvent(evt_type, domain, self.__name__, event)
                self.notifyListeners(evt)

                if self.sf.isDomain(domain, self.opts['_internettlds']):
                    if evt_type.startswith('AFFILIATE'):
                        evt = SpiderFootEvent('AFFILIATE_DOMAIN_NAME', domain, self.__name__, event)
                        self.notifyListeners(evt)
                    else:
                        evt = SpiderFootEvent('DOMAIN_NAME', domain, self.__name__, event)
                        self.notifyListeners(evt)

# End of sfp_virustotal class
