# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_hackertarget
# Purpose:      SpiderFoot plug-in to search HackerTarget.com for hosts sharing
#               the same IP. Optionally, also perform a basic TCP/UDP port scan
#               for commonly open ports using HackerTarget.com port scan tools.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     12/04/2014
# Copyright:   (c) Steve Micallef 2014
# Licence:     GPL
# -------------------------------------------------------------------------------

import json
import re
import urllib.error
import urllib.parse
import urllib.request

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_hackertarget(SpiderFootPlugin):

    meta = {
        'name': "HackerTarget",
        'summary': "Search HackerTarget.com for hosts sharing the same IP.",
        'flags': [],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Passive DNS"],
        'dataSource': {
            'website': "https://hackertarget.com/",
            'model': "FREE_NOAUTH_UNLIMITED",
            'references': [
                "https://hackertarget.com/research/",
                "https://hackertarget.com/category/tools/"
            ],
            'favIcon': "https://www.google.com/s2/favicons?domain=https://hackertarget.com/",
            'logo': "https://hackertarget.com/wp-content/uploads/2018/03/online-security.png",
            'description': "Simplify the security assessment process with hosted vulnerability scanners. "
            "From attack surface discovery to vulnerability identification, "
            "actionable network intelligence for IT & security operations. "
            "Proactively hunt for security weakness. "
            "Pivot from attack surface discovery to vulnerability identification.",
        }
    }

    opts = {
        'cohostsamedomain': False,
        'verify': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxcohost': 100,
        'http_headers': False,
    }

    optdescs = {
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        'http_headers': "Retrieve IP HTTP headers using HackerTarget.com",
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

    def watchedEvents(self):
        return [
            "IP_ADDRESS",
            "NETBLOCK_OWNER",
            'DOMAIN_NAME_PARENT'
        ]

    def producedEvents(self):
        return [
            "CO_HOSTED_SITE",
            "IP_ADDRESS",
            'WEBSERVER_HTTPHEADERS',
            'RAW_DNS_RECORDS',
            'INTERNET_NAME',
            'INTERNET_NAME_UNRESOLVED',
            'DOMAIN_NAME',
            'AFFILIATE_DOMAIN_NAME',
            'AFFILIATE_INTERNET_NAME',
            'AFFILIATE_INTERNET_NAME_UNRESOLVED'
        ]

    def httpHeaders(self, ip):
        """Retrieve HTTP headers for IP address

        Args:
            ip (str): IPv4 address

        Returns:
            dict: HTTP headers
        """
        params = urllib.parse.urlencode({
            'q': ip
        })

        res = self.sf.fetchUrl(
            f"https://api.hackertarget.com/httpheaders/?{params}",
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout']
        )

        if res['content'] is None:
            self.error(f"Unable to fetch HTTP headers for {ip} from HackerTarget.com.")
            return None

        if res['code'] == '429':
            self.error("You are being rate-limited by HackerTarget")
            self.errorState = True
            return None

        if not res['content'].startswith('HTTP/'):
            self.debug(f"Found no HTTP headers for {ip}")
            return None

        headers = dict()

        for header in res['content'].splitlines():
            if ': ' not in header:
                continue
            k = header.split(': ')[0].lower()
            v = ': '.join(header.split(': ')[1:])
            headers[k] = v

        return headers

    def zoneTransfer(self, ip):
        """Retrieve DNS zone transfer

        Args:
            ip (str): IPv4 address

        Returns:
            list: DNS zone
        """
        params = urllib.parse.urlencode({
            'q': ip
        })

        res = self.sf.fetchUrl(
            f"https://api.hackertarget.com/zonetransfer/?{params}",
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout']
        )

        if res['content'] is None:
            self.error(f"Unable to fetch DNS zone for {ip} from HackerTarget.com.")
            return None

        if res['code'] == '429':
            self.error("You are being rate-limited by HackerTarget")
            self.errorState = True
            return None

        records = list()

        for record in res['content'].splitlines():
            if record.strip().startswith(';'):
                continue
            if record.strip() == '':
                continue
            records.append(record.strip())

        return records

    def reverseIpLookup(self, ip):
        """Reverse lookup hosts on the same IP address

        Args:
            ip (str): IPv4 address

        Returns:
            list: (co)hosts on provided IP addresses
        """
        params = urllib.parse.urlencode({
            'q': ip
        })

        res = self.sf.fetchUrl(
            f"https://api.hackertarget.com/reverseiplookup/?{params}",
            useragent=self.opts['_useragent'],
            timeout=self.opts['_fetchtimeout']
        )

        if res['content'] is None:
            self.error("Unable to fetch hackertarget.com content.")
            return None

        if res['code'] == '429':
            self.error("You are being rate-limited by HackerTarget")
            self.errorState = True
            return None

        if "No records" in res['content']:
            return None

        hosts = res['content'].split('\n')

        self.debug(f"Found {len(hosts)} on {ip}")

        return hosts

    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if srcModuleName == "sfp_hackertarget" and eventName == "IP_ADDRESS":
            self.debug(f"Ignoring {eventName}, from self.")
            return

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return

            max_netblock = self.opts['maxnetblock']
            net_size = IPNetwork(eventData).prefixlen
            if net_size < max_netblock:
                self.debug(f"Network size bigger than permitted: {net_size} > {max_netblock}")
                return

        if eventName == 'DOMAIN_NAME_PARENT':
            records = self.zoneTransfer(eventData)

            if not records:
                return

            evt = SpiderFootEvent('RAW_DNS_RECORDS', "\n".join(records), self.__name__, event)
            self.notifyListeners(evt)

            # Try and pull out individual records
            for row in records:
                pat = re.compile(r"^(\S+)\.?\s+\d+\s+IN\s+[AC].*", re.IGNORECASE | re.DOTALL)
                grps = re.findall(pat, row)

                if len(grps) == 0:
                    continue

                hosts = list()

                for strdata in grps:
                    self.debug("Matched: " + strdata)
                    if strdata.endswith("."):
                        hosts.append(strdata[:-1])
                    else:
                        hosts.append(strdata)

                for host in set(hosts):
                    if self.getTarget().matches(host, includeChildren=True, includeParents=True):
                        evt_type = 'INTERNET_NAME'
                    else:
                        evt_type = 'AFFILIATE_INTERNET_NAME'

                    if self.opts['verify'] and not self.sf.resolveHost(host) and not self.sf.resolveHost6(host):
                        self.debug(f"Host {host} could not be resolved")
                        evt_type += '_UNRESOLVED'

                    evt = SpiderFootEvent(evt_type, host, self.__name__, event)
                    self.notifyListeners(evt)

                    if self.sf.isDomain(host, self.opts['_internettlds']):
                        if evt_type.startswith('AFFILIATE'):
                            evt = SpiderFootEvent('AFFILIATE_DOMAIN_NAME', host, self.__name__, event)
                            self.notifyListeners(evt)
                        else:
                            evt = SpiderFootEvent('DOMAIN_NAME', host, self.__name__, event)
                            self.notifyListeners(evt)

            return

        qrylist = list()
        if eventName.startswith("NETBLOCK_"):
            for ipaddr in IPNetwork(eventData):
                if str(ipaddr) not in self.results:
                    qrylist.append(str(ipaddr))
                    self.results[str(ipaddr)] = True
        else:
            qrylist.append(eventData)
            self.results[eventData] = True

        myres = list()

        for ip in qrylist:
            if self.checkForStop():
                return

            hosts = self.reverseIpLookup(ip)
            if not hosts:
                continue

            for h in hosts:
                if " " in h:
                    continue

                self.info(f"Found something on same IP: {h}")

                if not self.opts['cohostsamedomain']:
                    if self.getTarget().matches(h, includeParents=True):
                        self.debug(f"Skipping {h} because it is on the same domain.")
                        continue

                if h not in myres and h != ip:
                    if self.opts['verify'] and not self.sf.validateIP(h, ip):
                        self.debug(f"Host {h} no longer resolves to {ip}")
                        continue

                    if self.cohostcount < self.opts['maxcohost']:
                        # Create an IP Address event stemming from the netblock as the
                        # link to the co-host.
                        if eventName == "NETBLOCK_OWNER":
                            ipe = SpiderFootEvent("IP_ADDRESS", ip, self.__name__, event)
                            self.notifyListeners(ipe)
                            evt = SpiderFootEvent("CO_HOSTED_SITE", h.lower(), self.__name__, ipe)
                            self.notifyListeners(evt)
                        else:
                            evt = SpiderFootEvent("CO_HOSTED_SITE", h.lower(), self.__name__, event)
                            self.notifyListeners(evt)

                        myres.append(h.lower())
                        self.cohostcount += 1

            # For netblocks, we need to create the IP address event so that
            # the threat intel event is more meaningful.
            if eventName == 'NETBLOCK_OWNER':
                pevent = SpiderFootEvent("IP_ADDRESS", ip, self.__name__, event)
                self.notifyListeners(pevent)
            else:
                pevent = event

            if self.opts.get('http_headers', True):
                http_headers = self.httpHeaders(ip)
                if http_headers is not None:
                    e = SpiderFootEvent('WEBSERVER_HTTPHEADERS', json.dumps(http_headers), self.__name__, pevent)
                    e.actualSource = ip
                    self.notifyListeners(e)

# End of sfp_hackertarget class
