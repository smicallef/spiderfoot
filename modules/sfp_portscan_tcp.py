# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_portscan_tcp
# Purpose:      SpiderFoot plug-in for performing a basic TCP port scan of IP
#               addresses identified.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     20/02/2013
# Copyright:   (c) Steve Micallef 2013
# Licence:     GPL
# -------------------------------------------------------------------------------

from netaddr import IPAddress, IPNetwork
import socket
import random
import threading
import time
from sflib import SpiderFoot, SpiderFootPlugin, SpiderFootEvent


class sfp_portscan_tcp(SpiderFootPlugin):
    """Port Scanner - TCP:Footprint,Investigate:Crawling and Scanning:slow,invasive:Scans for commonly open TCP ports on Internet-facing systems."""


    # Default options
    opts = {
        # Commonly used ports on external-facing systems
        'ports': ['21', '22', '23', '25', '53', '79', '80', '81', '88', '110', '111',
                  '113', '119', '123', '137', '138', '139', '143', '161', '179',
                  '389', '443', '445', '465', '512', '513', '514', '515', '3306',
                  '5432', '1521', '2638', '1433', '3389', '5900', '5901', '5902',
                  '5903', '5631', '631', '636',
                  '990', '992', '993', '995', '1080', '8080', '8888', '9000'],
        'timeout': 15,
        'maxthreads': 10,
        'randomize': True,
        'netblockscan': True,
        'netblockscanmax': 24
    }

    # Option descriptions
    optdescs = {
        'maxthreads': "Number of ports to try to open simultaneously (number of threads to spawn at once.)",
        'ports': "The TCP ports to scan. Prefix with an '@' to iterate through a file containing ports to try (one per line), e.g. @C:\ports.txt or @/home/bob/ports.txt. Or supply a URL to load the list from there.",
        'timeout': "Seconds before giving up on a port.",
        'randomize': "Randomize the order of ports scanned.",
        'netblockscan': "Port scan all IPs within identified owned netblocks?",
        'netblockscanmax': "Maximum netblock/subnet size to scan IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    results = dict()
    portlist = list()
    portResults = dict()
    lock = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = dict()
        self.__dataSource__ = "Target Network"
        self.lock = threading.Lock()

        for opt in userOpts.keys():
            self.opts[opt] = userOpts[opt]

        if self.opts['ports'][0].startswith("http://") or \
                self.opts['ports'][0].startswith("https://") or \
                self.opts['ports'][0].startswith("@"):
            self.portlist = self.sf.optValueToData(self.opts['ports'][0])
        else:
            self.portlist = self.opts['ports']

        # Convert to integers
        self.portlist = [int(x) for x in self.portlist]

        if self.opts['randomize']:
            random.shuffle(self.portlist)

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'NETBLOCK_OWNER']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["TCP_PORT_OPEN", "TCP_PORT_OPEN_BANNER"]

    def tryPort(self, ip, port):
        try:
            sock = socket.create_connection((ip, port), self.opts['timeout'])
            sock.settimeout(self.opts['timeout'])
            with self.lock:
                self.portResults[ip + ":" + str(port)] = True
        except Exception as e:
            with self.lock:
                self.portResults[ip + ":" + str(port)] = False
            return

        # If the port was open, see what we can read
        try:
            with self.lock:
                self.portResults[ip + ":" + str(port)] = sock.recv(4096)
        except Exception as e:
            sock.close()
            return

        sock.close()

    def tryPortWrapper(self, ip, portList):
        self.portResults = dict()
        running = True
        i = 0
        t = []

        # Spawn threads for scanning
        while i < len(portList):
            self.sf.info("Spawning thread to check port: " + str(portList[i]) + " on " + ip)
            t.append(threading.Thread(name='sfp_portscan_tcp_' + str(portList[i]),
                                      target=self.tryPort, args=(ip, portList[i])))
            t[i].start()
            i += 1

        # Block until all threads are finished
        while running:
            found = False
            for rt in threading.enumerate():
                if rt.name.startswith("sfp_portscan_tcp_"):
                    found = True

            if not found:
                running = False
            time.sleep(0.25)

        return self.portResults

    # Generate TCP_PORT_OPEN_BANNER event
    def sendEvent(self, resArray, srcEvent):
        for cp in resArray:
            if resArray[cp]:
                self.sf.info("TCP Port " + cp + " found to be OPEN.")
                evt = SpiderFootEvent("TCP_PORT_OPEN", cp, self.__name__, srcEvent)
                self.notifyListeners(evt)
                if resArray[cp] != "" and resArray[cp] != True:
                    bevt = SpiderFootEvent("TCP_PORT_OPEN_BANNER", resArray[cp],
                                           self.__name__, evt)
                    self.notifyListeners(bevt)


    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data
        scanIps = list()

        self.sf.debug("Received event, " + eventName + ", from " + srcModuleName)

        try:
            if eventName == "NETBLOCK_OWNER" and self.opts['netblockscan']:
                net = IPNetwork(eventData)
                if net.prefixlen < self.opts['netblockscanmax']:
                    self.sf.debug("Skipping port scanning of " + eventData + ", too big.")
                    return None

                for ip in net:
                    ipaddr = str(ip)
                    if ipaddr.split(".")[3] in ['255', '0']:
                        continue
                    if '255' in ipaddr.split("."):
                        continue
                    scanIps.append(ipaddr)
            else:
                scanIps.append(eventData)
        except BaseException as e:
            self.sf.error("Strange netblock identified, unable to parse: " +
                          eventData + " (" + str(e) + ")", False)
            return None

        for ipAddr in scanIps:
            # Don't look up stuff twice
            if ipAddr in self.results:
                self.sf.debug("Skipping " + ipAddr + " as already scanned.")
                return None
            else:
                self.results[ipAddr] = True

            i = 0
            portArr = []
            for port in self.portlist:
                if self.checkForStop():
                    return None

                if i < self.opts['maxthreads']:
                    portArr.append(port)
                    i += 1
                else:
                    self.sendEvent(self.tryPortWrapper(ipAddr, portArr), event)
                    i = 1
                    portArr = [port]

            # Scan whatever is remaining
            self.sendEvent(self.tryPortWrapper(ipAddr, portArr), event)

# End of sfp_portscan_tcp class
