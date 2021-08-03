# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_nmap
# Purpose:      SpiderFoot plug-in for using nmap to perform OS fingerprinting.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     03/05/2020
# Copyright:   (c) Steve Micallef 2020
# Licence:     GPL
# -------------------------------------------------------------------------------

import os
from shutil import which
from pathlib import Path
from nmappalyzer import NmapScan

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_nmap(SpiderFootPlugin):

    meta = {
        'name': "Tool - Nmap",
        'summary': "Identify what Operating System might be used.",
        'flags': ["tool", "slow", "invasive"],
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
        'netblockscan': True,
        'netblockscanmax': 24
    }

    # Option descriptions
    optdescs = {
        'nmappath': "Path to nmap executable. Optional.",
        'topports': "Scan top commonly-open ports.",
        'ports': "Manually specify ports to scan, comma-separated. Overrides \"top ports\".",
        'netblockscan': "Port scan all IPs within identified owned netblocks?",
        'netblockscanmax': "Maximum netblock/subnet size to scan IPs within (CIDR value, 24 = /24, 16 = /16, etc.)"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()
        self.errorState = False
        self.__dataSource__ = "Target Network"

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

        self.ports = ""
        if self.opts["ports"]:
            try:
                for s in self.opts["ports"].split(","):
                    try:
                        # port should either be an int
                        port = int(s)
                        assert 0 <= port <= 65535
                    except ValueError:
                        # or an int range
                        high, low = s.split('-', 1)
                        high, low = int(high), int(low)
                        assert high >= low and all([0 <= x <= 65535 for x in (high, low)])
                self.ports = str(self.opts["ports"])
            except Exception:
                self.sf.error("Invalid \"ports\" setting. Defaulting to top ports.")

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
            self.sf.error(f"Error determining executable paths: {e}")
            self.errorState = True
            return

        # Build Nmap command-line arguments
        self.args = (
            # Treat all hosts as online -- skip host discovery
            '-Pn',
            # Never do DNS resolution
            '-n',
            # does the equivalent of --max-rtt-timeout 1250ms --min-rtt-timeout 100ms --initial-rtt-timeout 500ms
            # --max-retries 6 and sets the maximum TCP scan delay to 10 milliseconds.
            '-T4',
            # overrides --max-retries for faster results
            '--max-retries', '2',
            # Probe open ports to determine service/version info
            '-sV',
            # This is a convenience alias for --version-intensity 2.
            # This light mode makes version scanning much faster, but it is slightly less likely to identify services.
            '--version-light'
        )
        if self.ports:
            self.args += ("-p", self.ports)
        else:
            self.args += ("--top-ports", str(int(self.opts["topports"])))
        # if we're root, enable OS detection
        if not (os.name == "posix" and os.geteuid() != 0):
            # Enable OS detection
            self.args += ("-O",)
            # Limit OS detection to promising targets
            self.args += ("--osscan-limit",)

    # What events is this module interested in for input
    def watchedEvents(self):
        return ['IP_ADDRESS', 'INTERNET_NAME', 'NETBLOCK_OWNER']

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["OPERATING_SYSTEM", "TCP_PORT_OPEN", "UDP_PORT_OPEN", "TCP_PORT_OPEN_SSL", "LINKED_URL_INTERNAL"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if srcModuleName == "sfp_tool_nmap":
            self.sf.debug("Skipping event from myself.")
            return

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        if self.errorState:
            return

        # resolve hostnames to IPs
        targets = [eventData]
        if eventName == "INTERNET_NAME":
            targets = [t for t in self.sf.resolveHost(eventData) if self.sf.validIP(t) or self.sf.validIP6(t)]

        try:
            if eventName == "NETBLOCK_OWNER" and self.opts['netblockscan']:
                net = IPNetwork(eventData)
                targets = [eventData]
                if net.prefixlen < self.opts['netblockscanmax']:
                    self.sf.debug("Skipping port scanning of " + eventData + ", too big.")
                    return

        except Exception as e:
            self.sf.error("Strange netblock identified, unable to parse: " + eventData + " (" + str(e) + ")")
            return

        targets = [t for t in targets if not any([IPNetwork(t) in r for r in self.already_scanned])]

        if not targets:
            self.sf.debug(f"Skipping {eventData}, already scanned.")
            return

        for target in targets:
            self.results[str(target)] = True

        # Run scan
        scan = NmapScan(targets, self.args, nmap_executable=self.exe, start=False)
        self.sf.debug(f"Running nmap command: {' '.join(scan.command)}")
        scan.start()
        if scan._process.returncode != 0:
            self.sf.debug("Error running Nmap: " + scan.stderr + ", " + scan.stdout)
            return

        # Parse results
        for host in scan:

            # Look for open ports
            for open_port in host.open_ports:
                port, protocol = open_port.split("/")
                if protocol.lower() in ("tcp", "udp"):
                    open_port = f"{host.address}:{port}"
                    evt = SpiderFootEvent(f"{protocol.upper()}_PORT_OPEN", open_port, self.__name__, event)
                    self.notifyListeners(evt)

            # Look for HTTP and SSL
            for port_elem in host.etree.findall("ports/port"):
                port = port_elem.attrib.get("portid", "")
                protocol = port_elem.attrib.get("protocol", "").lower()
                for service in port_elem.findall("service"):
                    serviceName = service.attrib.get("name", "").lower()
                    tunnel = service.attrib.get("tunnel", "").lower()
                    if eventName == "INTERNET_NAME":
                        fqdn = eventData
                    else:
                        fqdn = host.address
                    # HTTP
                    if serviceName in ("http", "https"):
                        web_service = f"{serviceName}://{fqdn}:{port}"
                        if web_service not in self.results:
                            self.results[web_service] = True
                            evt = SpiderFootEvent("LINKED_URL_INTERNAL", web_service, self.__name__, event)
                            self.notifyListeners(evt)
                    # SSL
                    if port and protocol == "tcp" and tunnel in ("ssl", "tls"):
                        ssl_protocol = f"{host.address}:{port}"
                        evt = SpiderFootEvent("TCP_PORT_OPEN_SSL", ssl_protocol, self.__name__, event)
                        self.notifyListeners(evt)

            # Look for Operating Systems
            detectedOS = False
            for osMatch in host.etree.findall("os/osmatch"):
                try:
                    osName = osMatch.attrib.get("name", "")
                    accuracy = int(osMatch.attrib.get("accuracy", "0"))
                    if osName and accuracy >= 100:
                        evt = SpiderFootEvent("OPERATING_SYSTEM", osName, self.__name__, event)
                        self.notifyListeners(evt)
                        detectedOS = True
                        break
                except Exception:
                    continue
            if not detectedOS:
                self.sf.debug("Couldn't reliably detect the OS for " + eventData)

    @property
    def already_scanned(self):
        scanned = []
        for t in self.results:
            try:
                scanned.append(IPNetwork(t))
            except Exception:
                continue
        return scanned

# End of sfp_tool_nmap class
