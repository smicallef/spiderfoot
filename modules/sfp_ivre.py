# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_ivre
# Purpose:      Query an IVRE instance
#
# Author:      Pierre Lalet <pierre@droids-corp.org>
#
# Created:     2021-09-14
# Copyright:   (c) Pierre Lalet
# Licence:     GPL
# -------------------------------------------------------------------------------

import hashlib

from netaddr import IPNetwork
from ivre.db import db, DBPassive
from ivre import utils

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


def flt_from_asnum(dbase, asnum):
    return dbase.searchasnum(int(asnum))


def flt_from_ip(dbase, addr):
    yield dbase.searchhost(addr)


def flt_from_net(dbase, net):
    yield dbase.searchnet(net)


def flt_from_port(dbase, proto, port):
    try:
        yield dbase.searchport(port, protocol=proto)
    except ValueError:
        yield dbase.searchnonexistent()


def flt_from_cert(dbase, cert):
    yield dbase.searchcert(
        sha256=hashlib.new("sha256", utils.decode_b64(cert.encode())).hexdigest()
    )


def flt_from_fqdn(dbase, name):
    if isinstance(dbase, DBPassive):
        yield dbase.searchdns(name=name)
        yield dbase.searchdns(name=name, reverse=True)
    else:
        yield dbase.searchhostname(name)


EVENTS_FILTERS = {
    "BGP_AS_MEMBER": flt_from_asnum,
    "IP_ADDRESS": flt_from_ip,
    "IPV6_ADDRESS": flt_from_ip,
    "NETBLOCK_MEMBER": flt_from_net,
    # we probably don't want to get all hosts with port 80 open...
    # "TCP_PORT_OPEN": lambda dbase, port: flt_from_port(dbase, "tcp", port),
    # "UDP_PORT_OPEN": lambda dbase, port: flt_from_port(dbase, "udp", port),
    "SSL_CERTIFICATE_RAW": flt_from_cert,
    "INTERNET_NAME": flt_from_fqdn,
}


class sfp_ivre(SpiderFootPlugin):

    meta = {
        "name": "IVRE",
        "summary": "Obtain information from an IVRE instance.",
        # This module could be flagged as "tool", but it does not run
        # an external tool to collect data, it relies on data already
        # collected in IVRE.
        "flags": [],
        "useCases": ["Passive", "Footprint", "Investigate"],
        "categories": ["Search Engines"],
        "dataSource": {
            "website": "https://ivre.rocks/",
            "model": "PRIVATE_ONLY",
            "references": ["https://ivre.rocks/"],
            "favIcon": "https://ivre.rocks/favicon.ico",
            "logo": "https://ivre.rocks/logo-big.png",
            "description": "Unlike other modules, IVRE is not a service but "
            "an open-source software you need to run. Install an IVRE instance, "
            "configure it, and add your own data (scan results, passive intelligence).<br>"
            "<b>Important:</b> set the <code>use_passive</code>, <code>use_scans</code> "
            "and/or <code>use_data</code> settings to True to enable the module.<br>"
            "IVRE has several use-cases, such as running your own Shodan-like service "
            "(based on powerful open-source tools such as Masscan, Nmap, ZGrab2, ZDns), "
            "passively gather intelligence from network traffic (including running a "
            "Passive DNS service, collecting and analyzing X509 certificates, HTTP "
            "headers, TCP banners, etc.), analyzing scanners hits against simple "
            "honeypots, etc.<br>You may want to read "
            '<a href="https://doc.ivre.rocks/en/latest/usage/use-cases.html">IVRE use '
            "cases</a>.<br>"
        },
    }

    opts = {
        "check_asmembers_bool": False,
        "check_netmembers_bool": False,
        "check_asmembers_max": 4096,
        "check_netmembers_max": 24,
        "use_data": False,
        "use_passive": False,
        "use_scans": False,
    }

    optdescs = {
        "check_asmembers_bool": "Check hosts from AS numbers?",
        "check_netmembers_bool": "Check hosts from netblocks?",
        "check_asmembers_max": "If looking up AS members, the maximum number of addresses in an AS to look up all IPs within",
        "check_netmembers_max": "If looking up netblocks, the maximum netblock size to look up all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        "use_data": "Use data from the data purpose (MaxMind)",
        "use_passive": "Use data from the passive purpose",
        "use_scans": "Use data from the nmap (scans) purpose",
    }

    # Tracking results can be helpful to avoid reporting/processing duplicates
    results = None

    # Tracking the error state of the module can be useful to detect when a third party
    # has failed and you don't wish to process any more events.
    errorState = False

    def setup(self, sfc, userOpts=None):
        self.sf = sfc
        self.results = self.tempStorage()
        if userOpts is None:
            userOpts = {}

        for opt in list(userOpts):
            self.opts[opt] = userOpts[opt]

        self.db = db

    def watchedEvents(self):
        return list(EVENTS_FILTERS)
        # return [
        #     "BGP_AS_MEMBER",
        #     "NETBLOCK_MEMBER",
        #     "IP_ADDRESS",
        #     "IPV6_ADDRESS",
        #     "DOMAIN_NAME",
        #     "DOMAIN_NAME_PARENT",
        #     "INTERNET_NAME",
        #     "TCP_PORT_OPEN",
        #     "TCP_PORT_OPEN_BANNER",
        #     "WEBSERVER_BANNER",
        #     "WEBSERVER_HTTPHEADERS",
        #     "UDP_PORT_OPEN",
        #     "UDP_PORT_OPEN_INFO",
        #     "SSL_CERTIFICATE_RAW",
        # ]

    def producedEvents(self):
        return [
            "BGP_AS_MEMBER",
            "NETBLOCK_MEMBER",
            "IP_ADDRESS",
            "IPV6_ADDRESS",
            "DOMAIN_NAME",
            "DOMAIN_NAME_PARENT",
            "INTERNET_NAME",
            "TCP_PORT_OPEN",
            "TCP_PORT_OPEN_BANNER",
            "WEBSERVER_BANNER",
            "WEBSERVER_HTTPHEADERS",
            "UDP_PORT_OPEN",
            "UDP_PORT_OPEN_INFO",
            "SSL_CERTIFICATE_RAW",
            "GEOINFO",
            "COUNTRY_NAME",
            "SOFTWARE_USED",
            "USERNAME",
        ]

    _GEOINFO_KEYS = [
        ["city"],
        ["region_name", "region_code"],
        ["postal_code"],
        ["country_code", "country_name"],
    ]

    def handle_data_record(self, event, rec):
        if "country_name" in rec:
            yield SpiderFootEvent(
                "COUNTRY_NAME", rec["country_name"], self.__name__, event
            )
        elif "country_code" in rec:
            yield SpiderFootEvent(
                "COUNTRY_NAME", rec["country_code"], self.__name__, event
            )
        if "as_num" in rec:
            yield SpiderFootEvent(
                "BGP_AS_MEMBER", str(rec["as_num"]), self.__name__, event
            )
        if any(key in rec for keys in self._GEOINFO_KEYS for key in keys):
            location = []
            for keys in self._GEOINFO_KEYS:
                for key in keys:
                    if key in rec:
                        location.append(rec[key])
                        break
            yield SpiderFootEvent("GEOINFO", ", ".join(location), self.__name__, event)

    def handle_passive_record(self, event, rec):
        if "addr" in rec:
            if ":" in rec["addr"]:
                yield SpiderFootEvent("IPV6_ADDRESS", rec["addr"], self.__name__, event)
            else:
                yield SpiderFootEvent("IP_ADDRESS", rec["addr"], self.__name__, event)
        if rec["recontype"] == "DNS_ANSWER":
            names = [rec["value"]]
            if "targetval" in rec:
                names.append(rec["targetval"])
            for name in names:
                newevt = SpiderFootEvent("INTERNET_NAME", name, self.__name__, event)
                yield newevt
                if "." not in name:
                    continue
                domain = name.split(".", 1)[1]
                yield SpiderFootEvent("DOMAIN_NAME", domain, self.__name__, newevt)
            return
        if rec["recontype"] == "SSL_SERVER":
            if rec["source"] == "cert":
                yield SpiderFootEvent(
                    "SSL_CERTIFICATE_RAW",
                    utils.encode_b64(rec["value"]).decode(),
                    self.__name__,
                    event,
                )
            return
        if rec["recontype"] == "OPEN_PORT":
            yield SpiderFootEvent(
                f"{rec['source']}_PORT_OPEN",
                f"{rec['addr']}:{rec['port']}",
                self.__name__,
                event,
            )
            return
        if rec["recontype"] == "TCP_SERVER_BANNER":
            yield SpiderFootEvent(
                "TCP_PORT_OPEN_BANNER",
                rec["value"],
                self.__name__,
                event,
            )
            return

    def handle_nmap_record(self, event, rec):
        for hname in rec.get("hostnames", []):
            yield SpiderFootEvent("INTERNET_NAME", hname["name"], self.__name__, event)
        for port in rec.get("ports", []):
            if port["port"] != -1:
                if port["protocol"] in {"tcp", "udp"}:
                    yield SpiderFootEvent(
                        f"{port['protocol'].upper()}_PORT_OPEN",
                        f"{rec['addr']}:{port['port']}",
                        self.__name__,
                        event,
                    )
            for script in port.get("scripts", []):
                if script["id"] == "banner" and port["protocol"] == "tcp":
                    yield SpiderFootEvent(
                        "TCP_PORT_OPEN_BANNER",
                        script["output"],
                        self.__name__,
                        event,
                    )
                    continue
                if script["id"] == "ssl-cert":
                    for cert in script.get("ssl-cert", []):
                        if "pem" not in cert:
                            continue
                        yield SpiderFootEvent(
                            "SSL_CERTIFICATE_RAW",
                            "".join(cert["pem"].splitlines()[1:-1]),
                            self.__name__,
                            event,
                        )

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        # Once we are in this state, return immediately.
        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        # Don't look up stuff twice
        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already checked.")
            return

        self.results[eventData] = True

        # Data
        if self.opts["use_data"] and eventName in {"IP_ADDRESS", "IPV6_ADDRESS"}:
            self.handle_data_record(event, self.db.data.infos_byip(eventData) or {})

        if eventName == "NETBLOCK_OWNER":
            if not self.opts["check_netmembers_bool"]:
                self.debug("NETBLOCK_OWNER lookups disabled")
                return
            max_netblock = self.opts["check_netmembers_max"]
            net_size = IPNetwork(eventData).prefixlen
            if net_size < max_netblock:
                self.debug(
                    f"Network size {net_size} bigger than permitted: {max_netblock}"
                )
                return

        if eventName not in EVENTS_FILTERS:
            self.debug(f"Event {eventName} not handled")
            return

        find_flt = EVENTS_FILTERS[eventName]

        for dbase, run, handler in [
            (self.db.passive, self.opts["use_passive"], self.handle_passive_record),
            (self.db.nmap, self.opts["use_scans"], self.handle_nmap_record),
        ]:

            if self.checkForStop():
                return

            if not run:
                continue

            for flt in find_flt(dbase, eventData):
                for rec in dbase.get(flt):
                    self.debug(f"Record! {rec}")
                    for evt in handler(event, rec):
                        if evt.data != eventData:
                            self.notifyListeners(evt)
