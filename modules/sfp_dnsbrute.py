# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dnsbrute
# Purpose:      SpiderFoot plug-in for attempting to resolve through brute-forcing
#               common hostnames.
#
# Author:      Steve Micallef <steve@binarypool.com>, TheTechromancer
#
# Created:     05/19/2021
# Copyright:   (c) Steve Micallef 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import re
import random
import threading
import dns.resolver
from time import sleep
from csv import DictReader
from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_dnsbrute(SpiderFootPlugin):

    meta = {
        'name': "DNS Brute-forcer",
        'summary': "Attempts to identify hostnames through brute-forcing common names and iterations.",
        'flags': [""],
        'useCases': ["Footprint", "Investigate"],
        'categories': ["DNS"]
    }

    # Default options
    opts = {
        "domainonly": True,
        "numbermutation": True,
        "alphamutation": True,
        "_maxthreads": 100
    }

    # Option descriptions
    optdescs = {
        "domainonly": "Only attempt to brute-force names on domain names, not hostnames (some hostnames are also sub-domains).",
        "numbermutation": "For any host found, increment/decrement existing numbers (if any) and try appending 1, 01, 001, -1, -01, -001, 2, 02, etc. (up to 10)",
        "alphamutation": "For any host found, try common mutations such as -test, -old, etc.",
        "_maxthreads": "Maximum threads"
    }

    _ipRegex = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.sf.debug("Setting up sfp_dnsbrute")
        self.state = self.tempStorage()
        self.state.update({
            "sub_wordlist": [],
            "valid_hosts": [],
            "sent_events": [],
            "handled_events": [],
            "wildcards": dict()
        })
        self.__dataSource__ = "DNS"
        self.lock = threading.Lock()
        self.iteration = 0

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

        self.word_regex = re.compile(r'[^\d\W_]+')
        self.word_num_regex = re.compile(r'[^\W_]+')
        self.num_regex = re.compile(r'\d+')

        dicts_dir = f"{self.sf.myPath()}/spiderfoot/dicts/"
        with open(f"{dicts_dir}/subdomains.txt", "r") as f:
            self.state["sub_wordlist"] = list(set([x.strip().lower() for x in f.readlines()]))
        with open(f"{dicts_dir}/subdomain_mutations_alpha.txt", "r") as f:
            if self.opts["alphamutation"]:
                self.state["alpha_mutation_wordlist"] = list(set([x.strip().lower() for x in f.readlines()]))

        # set up nameservers
        self.resolvers = []
        nameservers = set()
        nameservers_url = "https://public-dns.info/nameservers.csv"
        nameservers_dict = self.sf.myPath() + "/dicts/resolvers.txt"
        # get every valid nameserver with 95% or higher reliability
        fetched_nameservers = str(self.sf.fetchUrl(
            nameservers_url,
            useragent=self.opts.get("_useragent", "Spiderfoot")
        )["content"])
        for line in DictReader(fetched_nameservers.splitlines()):
            ip_address = str(line.get("ip_address", "")).strip()
            try:
                reliability = float(line.get("reliability", 0))
            except ValueError:
                continue
            if reliability >= .95 and self._ipRegex.match(ip_address):
                nameservers.add(ip_address)
        # fall back to local dict if necessary
        if not nameservers:
            self.sf.debug(f"Failed to retrieve nameservers from {nameservers_url}")
            nameservers = set(self._ipRegex.findall(open(nameservers_dict, "r").read()))
            self.sf.debug(f"Loaded {len(nameservers):,} nameservers from {nameservers_dict}")
        else:
            self.sf.debug(f"Loaded {len(nameservers):,} nameservers from {nameservers_url}")
        self.verifyNameservers(nameservers)

    def resolve(self, host, tries=10, nameserver=None):
        if nameserver is None:
            resolver = self.getResolver()
        else:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [nameserver]

        self.sf.debug(f"Resolving {host} using nameserver {resolver.nameservers[0]}")

        ips = set()
        for recordType in ["A", "AAAA"]:
            try:
                for answer in resolver.resolve(host, recordType):
                    ips.add(str(answer))
                break
            except dns.resolver.NXDOMAIN:
                break
            except Exception as e:
                self.sf.debug(f"Error resolving \"{host}\": {e.__class__.__name__}: {e}")
                if tries > 0:
                    self.sf.debug(f"Retrying \"{host}\"")
                    return self.resolve(host, tries=tries - 1, nameserver=nameserver)
                else:
                    self.sf.debug(f"Max retries ({tries:,}) exceeded for \"{host}\"")
                    return (host, [])

        return (host, list(ips))

    def isWildcard(self, target, ips):
        """Checks if host+ips came from a wildcard DNS configuration
        Note: allows the first result through, so one entry is preserved

        Args:
            target (str): hostname
            ips (list): resolved IP addresses of hostname

        Returns:
            boolean: whether the host came from a wildcard DNS configuration
        """
        wildcard = False
        host, domain = str(target).split(".", 1)

        # if we've already checked this domain:
        if domain in self.state["wildcards"]:
            if all([ip in self.state["wildcards"][domain] for ip in ips]):
                wildcard = True
        else:
            self.state["wildcards"][domain] = self.getWildcardIPs(domain)

        return wildcard

    def getWildcardIPs(self, domain):
        randpool = "bcdfghjklmnpqrstvwxyz3456789"
        randhost = "".join([random.SystemRandom().choice(randpool) for x in range(10)]) + "." + domain
        return list(set([str(s) for s in self.resolve(randhost)[-1]]))

    def getResolver(self):
        with self.lock:
            self.iteration += 1
            return self.resolvers[self.iteration % len(self.resolvers)]

    def verifyNameservers(self, nameservers, timeout=2):
        """Check each resolver to make sure it can actually resolve DNS names

        Args:
            nameservers (list): nameservers to verify
            timeout (int): timeout for dns query

        Returns:
            boolean: whether any of the nameservers are valid
        """
        for nameserver in nameservers:
            threading.Thread(name=f"sfp_dnsbrute_{nameserver}", target=self.verifyNameserver, args=(nameserver, timeout)).start()
        sleep(timeout)
        if len(self.resolvers) > 0:
            self.sf.debug(f"Using {len(self.resolvers):,} valid nameservers")
            return True
        else:
            return False

    def verifyNameserver(self, nameserver, timeout=2):
        """Validate a nameserver by making a sample query and a garbage query

        Args:
            nameserver (str): nameserver to verify
            timeout (int): timeout for dns query

        Returns:
            boolean: whether the nameserver is valid
        """
        valid = True

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.nameservers = [nameserver]

        # first, make sure it can resolve google.com
        try:
            resolver.query("www.google.com", "A")
        except Exception:
            valid = False

        # then, make sure it isn't feeding us garbage data
        randpool = "bcdfghjklmnpqrstvwxyz3456789"
        randhost = "".join([random.SystemRandom().choice(randpool) for x in range(10)]) + ".google.com"
        try:
            results = list(resolver.query(randhost, "A"))
            if results:
                self.sf.debug(f"Garbage data from nameserver: {nameserver}")
                valid = False
        except Exception as e:
            self.sf.debug(f"Garbage query to nameserver {nameserver} failed successfully: {e}")

        if valid:
            self.sf.debug(f"Valid nameserver: {nameserver}")
            with self.lock:
                self.resolvers.append(resolver)
        else:
            self.sf.debug(f"Invalid nameserver: {nameserver}")

        return valid

    # What events is this module interested in for input
    def watchedEvents(self):
        ret = ["DOMAIN_NAME"]
        if not self.opts["domainonly"] or self.opts["numbermutation"] or self.opts["alphamutation"]:
            ret += ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]
        return ret

    def producedEvents(self):
        return ["INTERNET_NAME"]

    def isValidHost(self, host, ips):
        """Verify that the record is valid, not a duplicate, and not resulting from wildcard DNS

        Args:
            host (str): host to validate
            ips (list): IP addresses for hostname

        Returns:
            boolean: whether the record is valid
        """
        # make double-sure that this host actually exists
        ips_google = self.resolve(host, nameserver="8.8.8.8")[1]
        ips_cloudflare = self.resolve(host, nameserver="1.1.1.1")[1]
        if not ips_google or not ips_cloudflare:
            self.sf.debug(f"Incorrectly-reported subdomain {host} does not exist.")
            return False

        # if we haven't seen the host before
        if host not in self.state["valid_hosts"]:
            # and it isn't a wildcard
            if not self.isWildcard(host, ips):
                # then we're good
                return True
            else:
                self.sf.debug(f"Invalid wildcard host: {host}")
        else:
            self.sf.debug(f"Already processed host: {host}")

        return False

    def sendEvent(self, source, host, ips, method=None):
        if method is None:
            method = ""
        host = host.lower()
        # skip if we've already sent this event
        eventDataHash = self.sf.hashstring(host)
        if eventDataHash in self.state["sent_events"]:
            self.sf.debug("Skipping already-sent event")
            return
        elif eventDataHash in self.state["handled_events"]:
            self.sf.debug("Not sending already-handled event")
            return
        self.state["sent_events"].append(eventDataHash)

        if ips and self.isValidHost(host, ips):
            self.state["valid_hosts"].append(host)
            self.sf.info(f"Found subdomain via {method}: {host}")
            # Report the host
            e = SpiderFootEvent("INTERNET_NAME", host, self.__name__, source)
            self.notifyListeners(e)

    def getNumberMutations(self, host, num=10):
        subdomains = set()
        host, domain = host.split(".", 1)

        # detects numbers and increments/decrements them
        # e.g. for "host2-p013", we would try:
        # - "host0-p013" through "host12-p013"
        # - "host2-p003" through "host2-p023"
        # limited to three iterations for sanity's sake
        for match in list(self.num_regex.finditer(host))[-3:]:
            span = match.span()
            before = host[:span[0]]
            after = host[span[-1]:]
            number = host[span[0]:span[-1]]
            numlen = len(number)
            maxnum = min(int("9" * numlen), int(number) + num)
            minnum = max(0, int(number) - num)
            for i in range(minnum, maxnum + 1):
                subdomains.add(f"{before}{str(i).zfill(numlen)}{after}")
                if not number.startswith("0"):
                    subdomains.add(f"{before}{i}{after}")

        # appends numbers after each word
        # e.g., for "host-www", we would try:
        # - "host1-www", "host2-www", etc.
        # - "host-www1", "host-www2", etc.
        # limited to three iterations for sanity's sake
        suffixes = ["", "0", "00", "-", "-0", "-00"]
        for match in list(self.word_regex.finditer(host))[-3:]:
            for s in suffixes:
                for i in range(num):
                    span = match.span()
                    before = host[:span[-1]]
                    after = host[span[-1]:]
                    subdomains.add(f"{before}{s}{i}{after}")
        # basic case so we don't miss anything
        for s in suffixes:
            for i in range(num):
                subdomains.add(f"{host}{s}{i}")

        # ensure we aren't including the source subdomain
        try:
            subdomains.remove(host)
        except KeyError:
            pass

        return subdomains

    def getAlphaMutations(self, host):
        subdomains = set()
        host, domain = host.split(".", 1)

        # if the input is "host01-www", it tries "host" and "www"
        # or if the input is "host01", it tries "host"
        for m in self.word_regex.findall(host):
            if m != host:
                subdomains.add(m)
        # same thing but including numbers
        # if the input is "host01-www", it tries "host01" and "www"
        for m in self.word_num_regex.findall(host):
            if m != host:
                subdomains.add(m)

        # host-dev, www-host, etc.
        for m in self.state["alpha_mutation_wordlist"]:
            subdomains.add(f"{host}{m}")
            subdomains.add(f"{host}-{m}")
            subdomains.add(f"{m}{host}")
            subdomains.add(f"{m}-{host}")

        # ensure we aren't including the source subdomain
        try:
            subdomains.remove(host)
        except KeyError:
            pass

        return subdomains

    def bruteSubdomains(self, host, subdomains, threads):
        self.sf.info(f"Resolving {len(subdomains):,} subdomains with {threads:,} threads.")

        with self.threadPool(threads=threads, name='sfp_dnsbrute_subdomains') as pool:
            for hostname, ips in pool.map(
                [f"{sub}.{host}" for sub in subdomains],
                self.resolve,
            ):
                if ips:
                    yield (hostname, ips)

    def handleEvent(self, event):
        if not self.resolvers:
            self.sf.error("No valid DNS resolvers")
            return

        host = str(event.data).lower()

        self.sf.debug(f"Received event, {event.eventType}, from {event.module}")

        # skip if we've already processed this event
        eventDataHash = self.sf.hashstring(host)
        if eventDataHash in self.state["handled_events"]:
            self.sf.debug(f"Skipping already-processed event, {event.eventType}, from {event.module}")
            return
        self.state["handled_events"].append(eventDataHash)

        subdomains = set()
        method = "brute-force"
        base = str(host)
        threads = int(self.opts["_maxthreads"])
        # if this isn't the main target, we can still do mutations
        if event.eventType in ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"] and not self.getTarget().matches(event.data, includeChildren=False):
            if self.opts["numbermutation"]:
                numberMutations = self.getNumberMutations(host)
                self.sf.debug(f"Generated {len(numberMutations):,} number mutations of {host}")
                subdomains.update(numberMutations)
            if self.opts["alphamutation"]:
                alphaMutations = self.getAlphaMutations(host)
                self.sf.debug(f"Generated {len(alphaMutations):,} alpha mutations of {host}")
                subdomains.update(alphaMutations)
            method = "mutation"
            base = host.split(".", 1)[-1]
            threads = min(int(len(subdomains) / 3) + 1, self.opts["_maxthreads"])
        # if this is the main target or we're brute-forcing subdomains of subdomains
        if self.getTarget().matches(event.data, includeChildren=False) or not self.opts["domainonly"]:
            subdomains.update(set(self.state["sub_wordlist"]))
            threads = int(self.opts["_maxthreads"])

        # subdomain brute force
        for hostname, ips in self.bruteSubdomains(base, subdomains, threads=threads):
            self.sendEvent(event, hostname, ips, method)
