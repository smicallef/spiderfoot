# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_nmap
# Purpose:      SpiderFoot plug-in for using nmap to perform OS fingerprinting.
#
# Author:      Steve Micallef <steve@binarypool.com>, TheTechromancer
#
# Created:     03/05/2020
# Copyright:   (c) Steve Micallef 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import os
import threading
from shutil import which
from pathlib import Path
from contextlib import suppress
from ipaddress import ip_network
from nmappalyzer import NmapScan

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_nmap(SpiderFootPlugin):

    meta = {
        'name': "Tool - Nmap",
        'summary': "Port scan to identify open ports, URLs, and operating systems.",
        'flags': ["tool", "invasive"],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["Crawling and Scanning"],
        'toolDetails': {
            'name': "Nmap",
            'description': "Nmap (\"Network Mapper\") is a free and open source utility for network discovery and security auditing.\n"
            "Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, "
            "what services (application name and version) those hosts are offering, "
            "what operating systems (and OS versions) they are running, "
            "what type of packet filters/firewalls are in use, and dozens of other characteristics.\n",
            'website': "https://nmap.org/",
            'repository': "https://svn.nmap.org/nmap"
        },
    }

    # Default options
    opts = {
        'nmappath': "",
        'topports': 1000,
        'ports': '',
        'timing': 4,
        'netblockscan': True,
        'netblockscanmax': 24,
        'batchsize': 16,
        'maxthreads': 4
    }

    # Option descriptions
    optdescs = {
        'nmappath': "Path to nmap executable. Optional.",
        'topports': "Scan top commonly-open ports.",
        'ports': "Manually specify ports to scan, comma-separated. Overrides \"top ports\".",
        'timing': "Scanning speed, 0-5.",
        'netblockscan': "Port scan all IPs within identified owned netblocks?",
        'netblockscanmax': "Maximum netblock/subnet size to scan IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'batchsize': "Scan in batches of this size.",
        'maxthreads': "Maximum number of scans to run at one time"
    }

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.targetPool = dict()
        self.errorState = False
        self.__dataSource__ = "Target Network"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

        # Normalize path
        if self.opts["nmappath"]:
            if Path(self.opts['nmappath']).is_dir():
                self.exe = str(Path(self.opts['nmappath']) / "nmap")
        else:
            self.exe = which("nmap") or "nmap"

        # Make sure executable exists
        try:
            assert (self.exe and Path(self.exe).is_file()),\
                "Unable to find nmap, please set path"
        except Exception as e:
            self.error(f"Error determining executable paths: {e}")
            self.errorState = True
            return

        # Build Nmap command-line arguments
        self.args = (
            # Treat all hosts as online -- skip host discovery
            '-Pn',
            # Never do DNS resolution
            '-n',
            # overrides --max-retries for faster results
            '--max-retries', '2',
            # Nmap has the ability to port scan or version scan multiple hosts in parallel
            # Nmap does this by dividing the target IP space into groups and then scanning
            # one group at a time. In general, larger groups are more efficient.
            '--min-hostgroup', str(self.opts['batchsize']),
            # Disable runtime interactions via keyboard
            '--noninteractive'
        )
        if self.opts['ports']:
            self.args += ("-p", self.opts['ports'])
        else:
            self.args += ("--top-ports", str(int(self.opts["topports"])))
        # if we're root, enable OS detection
        if not (os.name == "posix" and os.geteuid() != 0):
            # Enable OS detection
            self.args += ("-O",)
            # Limit OS detection to promising targets
            self.args += ("--osscan-limit",)
        # -T4 does the equivalent of --max-rtt-timeout 1250ms --min-rtt-timeout 100ms --initial-rtt-timeout 500ms
        # --max-retries 6 and sets the maximum TCP scan delay to 10 milliseconds.
        self.args += (f"-T{max(0, min(5, int(self.opts['timing'])))}",)
        self.lock = threading.Lock()

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'INTERNET_NAME', 'NETBLOCK_OWNER']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["OPERATING_SYSTEM", "TCP_PORT_OPEN", "UDP_PORT_OPEN", "LINKED_URL_INTERNAL"]

    # Handle events sent to this module
    def handleEvent(self, event):
        if event.module == "sfp_tool_nmap":
            self.debug("Skipping event from myself.")
            return

        self.debug(f"Received event, {event.eventType}, from {event.module}")

        if self.errorState:
            return

        # resolve hostnames to IPs
        targets = [event.data]
        if event.eventType == "INTERNET_NAME":
            targets = [t for t in self.sf.resolveHost(event.data) if self.sf.validIP(t) or self.sf.validIP6(t)]

        try:
            if event.eventType == "NETBLOCK_OWNER" and self.opts['netblockscan']:
                net = ip_network(event.data, strict=False)
                if net.prefixlen < self.opts['netblockscanmax']:
                    self.debug("Skipping port scanning of " + event.data + ", too big.")
                    return

        except Exception as e:
            self.error("Strange netblock identified, unable to parse: " + event.data + " (" + str(e) + ")")
            return

        newTargets = []
        for t in targets:
            t_net = ip_network(t, strict=False)
            if not any([t_net in r or t_net == r for r in self.alreadyScannedHosts]):
                newTargets.append(t)

        if newTargets:
            self.debug(f"Adding {len(newTargets):,} targets to batch.")
            for target in newTargets:
                self.targetPool[target] = event
        else:
            self.debug(f"Skipping {event.data}, already scanned.")
            return

        if 0 < self.numHostsWaiting >= self.opts['batchsize']:
            self.submitScan()

    def finish(self):
        if self.numHostsWaiting > 0:
            self.debug("Starting final Nmap scan.")
            self.submitScan()
        else:
            self.debug("Nmap scans finished.")

    def submitScan(self):
        with self.lock:
            targetPool = dict(self.targetPool)
            for target in targetPool:
                self.results[target] = True
            self.targetPool.clear()
        self.sharedThreadPool.submit(self.scan, targetPool, taskName=f"{self.__name__}_scan")

    def scan(self, targetPool):
        self.info(f"Scanning {len(targetPool):,} targets.")
        scan = NmapScan(list(targetPool.keys()), self.args, nmap_executable=self.exe, start=False)
        self.debug(f"Running nmap command: {' '.join(scan.command)}")
        scan.start()
        if scan._process.returncode != 0:
            self.debug("Error running Nmap: " + scan.stderr + ", " + scan.stdout)
            return

        # Parse results
        for host in scan:
            sourceEvent = None
            for target, event in targetPool.items():
                targetAddr = ip_network(target, strict=False)
                hostAddr = ip_network(f"{host.address}/{targetAddr.prefixlen}", strict=False)
                if hostAddr == targetAddr:
                    sourceEvent = event
                    break
            if sourceEvent is None:
                self.error(f"{host.address} not found in {list(self.targetPool.keys())}")
                continue
            # Look for open ports
            for open_port in host.open_ports:
                port, protocol = open_port.split("/", 1)
                if protocol.lower() in ("tcp", "udp"):
                    open_port = f"{host.address}:{port}"
                    evt = SpiderFootEvent(f"{protocol.upper()}_PORT_OPEN", open_port, self.__name__, sourceEvent)
                    self.notifyListeners(evt)

            # Look for HTTP and SSL
            for port_elem in host.etree.findall("ports/port"):
                port = port_elem.attrib.get("portid", "")
                protocol = port_elem.attrib.get("protocol", "").lower()
                for service in port_elem.findall("service"):
                    serviceName = service.attrib.get("name", "").lower()
                    tunnel = service.attrib.get("tunnel", "").lower()
                    if sourceEvent.eventType == "INTERNET_NAME":
                        fqdn = sourceEvent.data
                    else:
                        fqdn = host.address
                    # HTTP
                    if serviceName in ("http", "https"):
                        if tunnel in ("ssl", "tls"):
                            serviceName = "https"
                        web_service = f"{serviceName}://{fqdn}:{port}"
                        if web_service not in self.results:
                            self.results[web_service] = True
                            evt = SpiderFootEvent("LINKED_URL_INTERNAL", web_service, self.__name__, sourceEvent)
                            self.notifyListeners(evt)

            # Look for Operating Systems
            detectedOS = False
            for osMatch in host.etree.findall("os/osmatch"):
                try:
                    osName = osMatch.attrib.get("name", "")
                    accuracy = int(osMatch.attrib.get("accuracy", "0"))
                    if osName and accuracy >= 100:
                        evt = SpiderFootEvent("OPERATING_SYSTEM", osName, self.__name__, sourceEvent)
                        self.notifyListeners(evt)
                        detectedOS = True
                        break
                except Exception:
                    continue
            if not detectedOS:
                self.debug("Couldn't reliably detect the OS for " + sourceEvent.data)

    @property
    def running(self):
        return super().running or self.sharedThreadPool.countQueuedTasks(f"{self.__name__}_scan") > 0

    @property
    def numHostsWaiting(self):
        hostsWaiting = 0
        with self.lock:
            for target in self.targetPool.keys():
                hostsWaiting += ip_network(target, strict=False).num_addresses
        return hostsWaiting

    @property
    def alreadyScannedHosts(self):
        scanned = []
        with self.lock:
            for t in self.results:
                with suppress(Exception):
                    scanned.append(ip_network(t, strict=False))
        return scanned

# End of sfp_tool_nmap class
