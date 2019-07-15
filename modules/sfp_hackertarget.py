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
import socket
from netaddr import IPNetwork
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_hackertarget(SpiderFootPlugin):
    """HackerTarget.com:Footprint,Investigate,Passive:Passive DNS::Search HackerTarget.com for hosts sharing the same IP."""


    # Default options
    opts = {
        'cohostsamedomain': False,
        'verify': True,
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxcohost': 100,
        'http_headers': False,
        'tcp_portscan': False,
        'udp_portscan': False
    }

    # Option descriptions
    optdescs = {
        'cohostsamedomain': "Treat co-hosted sites on the same target domain as co-hosting?",
        'verify': "Verify co-hosts are valid by checking if they still resolve to the shared IP.",
        'netblocklookup': "Look up all IPs on netblocks deemed to be owned by your target for possible blacklisted hosts on the same target subdomain/domain?",
        'maxnetblock': "If looking up owned netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxcohost': "Stop reporting co-hosted sites after this many are found, as it would likely indicate web hosting.",
        'http_headers': "Retrieve IP HTTP headers using HackerTarget.com",
        'tcp_portscan': "Scan IP for commonly open TCP ports using HackerTarget.com TCP port scan.",
        'udp_portscan': "Scan IP for commonly open UDP ports using HackerTarget.com UDP port scan."
    }

    results = dict()
    cohostcount = 0

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.cohostcount = 0

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["IP_ADDRESS", "NETBLOCK_OWNER"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["CO_HOSTED_SITE", "UDP_PORT_OPEN", "TCP_PORT_OPEN", "IP_ADDRESS",
                'WEBSERVER_HTTPHEADERS']

    def validateIP(self, host, ip):
        try:
            addrs = socket.gethostbyname_ex(host)
        except BaseException as e:
            self.sf.debug("Unable to resolve " + host + ": " + str(e))
            return False

        for addr in addrs:
            if type(addr) == list:
                for a in addr:
                    if str(a) == ip:
                        return True
            else:
                if str(addr) == ip:
                    return True
        return False

    # Port scan for commonly open UDP ports
    def portScanUDP(self, ip):
        res = self.sf.fetchUrl("https://hackertarget.com/udp-port-scan/", timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'],
                               postData="theinput=" + ip + "&thetest=udpscan&name_of_nonce_field=&_wp_http_referer=%2Fudp-port-scan%2F")

        if res['content'] is None:
            return None

        html_data = re.findall(r'<pre id="formResponse">(.*?)</pre>', res['content'], re.MULTILINE | re.DOTALL)

        if not html_data:
            self.sf.debug("Found no open UDP ports on " + ip)
            return None

        open_ports = re.findall(r'(\d+)/udp\s+open\s+', html_data[0])

        if not open_ports:
            self.sf.debug("Found no open UDP ports on " + ip)
            return None

        self.sf.debug("Found " + str(len(open_ports)) + " open UDP ports on " + ip)

        return open_ports

    # Port scan for commonly open TCP ports
    def portScanTCP(self, ip):
        res = self.sf.fetchUrl("https://hackertarget.com/tcp-port-scan/", timeout=self.opts['_fetchtimeout'],
                               useragent=self.opts['_useragent'],
                               postData="theinput=" + ip + "&thetest=tcpscan&name_of_nonce_field=&_wp_http_referer=%2Ftcp-port-scan%2F")

        if res['content'] is None:
            return None

        html_data = re.findall(r'<pre id="formResponse">(.*?)</pre>', res['content'], re.MULTILINE | re.DOTALL)

        if not html_data:
            self.sf.debug("Found no open TCP ports on " + ip)
            return None

        open_ports = re.findall(r'(\d+)/tcp\s+open\s+', html_data[0])

        if not open_ports:
            self.sf.debug("Found no open TCP ports on " + ip)
            return None

        self.sf.debug("Found " + str(len(open_ports)) + " open TCP ports on " + ip)

        return open_ports

    # Retrieve HTTP headers
    def httpHeaders(self, ip):
        res = self.sf.fetchUrl("https://api.hackertarget.com/httpheaders/?q=" + ip,
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])

        if res['content'] is None:
            self.sf.error("Unable to fetch HTTP headers for " + ip + " from HackerTarget.com.", False)
            return None

        if not res['content'].startswith('HTTP/'):
            self.sf.debug("Found no HTTP headers for " + ip)
            return None

        headers = dict()

        for header in res['content'].splitlines():
            if ': ' not in header:
                continue
            k = header.split(': ')[0].lower()
            v = ': '.join(header.split(': ')[1:])
            headers[k] = v

        return headers

    # Reverse lookup hosts on the same IP address
    def reverseIpLookup(self, ip):
        res = self.sf.fetchUrl("http://api.hackertarget.com/reverseiplookup/?q=" + ip,
                               useragent=self.opts['_useragent'],
                               timeout=self.opts['_fetchtimeout'])
        if res['content'] is None:
            self.sf.error("Unable to fetch hackertarget.com content.", False)
            return None

        if "No records" in res['content']:
            return None

        hosts = res['content'].split('\n')

        self.sf.debug("Found " + str(len(hosts)) + " on " + ip)

        return hosts

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        self.currentEventSrc = event

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        if srcModuleName == "sfp_hackertarget" and eventName == "IP_ADDRESS":
            self.sf.debug("Ignoring " + eventName + ", from self.")
            return None

        # Don't look up stuff twice
        if eventData in self.results:
            self.sf.debug("Skipping " + eventData + " as already mapped.")
            return None

        if eventName == 'NETBLOCK_OWNER':
            if not self.opts['netblocklookup']:
                return None
            else:
                if IPNetwork(eventData).prefixlen < self.opts['maxnetblock']:
                    self.sf.debug("Network size bigger than permitted: " +
                                  str(IPNetwork(eventData).prefixlen) + " > " +
                                  str(self.opts['maxnetblock']))
                    return None

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
                return None

            hosts = self.reverseIpLookup(ip)

            for h in hosts:
                if " " in h:
                    continue

                self.sf.info("Found something on same IP: " + h)

                if not self.opts['cohostsamedomain']:
                    if self.getTarget().matches(h, includeParents=True):
                        self.sf.debug("Skipping " + h + " because it is on the same domain.")
                        continue

                if h not in myres and h != ip:
                    if self.opts['verify'] and not self.validateIP(h, ip):
                        self.sf.debug("Host " + h + " no longer resolves to " + ip)
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

            if self.opts.get('http_headers', True):
                http_headers = self.httpHeaders(ip)
                if http_headers is not None:
                    e = SpiderFootEvent('WEBSERVER_HTTPHEADERS', json.dumps(http_headers), self.__name__, event)
                    self.notifyListeners(e)

            if self.opts.get('udp_portscan', True):
                udp_ports = self.portScanUDP(ip)
                for port in udp_ports:
                    e = SpiderFootEvent("UDP_PORT_OPEN", ip + ":" + port, self.__name__, event)
                    self.notifyListeners(e)

            if self.opts.get('tcp_portscan', True):
                tcp_ports = self.portScanTCP(ip)
                for port in tcp_ports:
                    e = SpiderFootEvent("TCP_PORT_OPEN", ip + ":" + port, self.__name__, event)
                    self.notifyListeners(e)

# End of sfp_hackertarget class
