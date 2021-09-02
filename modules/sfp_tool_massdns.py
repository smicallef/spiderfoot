# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_tool_massdns
# Purpose:      SpiderFoot plug-in for attempting to resolve through brute-forcing
#               common hostnames.
#
# Author:      Steve Micallef <steve@binarypool.com>, TheTechromancer
#
# Created:     05/19/2021
# Copyright:   (c) Steve Micallef 2021
# Licence:     GPL
# -------------------------------------------------------------------------------

import datetime
import json
import random
import re
import subprocess
import tempfile
from contextlib import suppress
from pathlib import Path
from shutil import which

import dns.resolver

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_tool_massdns(SpiderFootPlugin):

    meta = {
        'name': "MassDNS",
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
        "large_wordlist": False,
        "concurrent_resolvers": 1000,
        "shuffledns_path": "",
        "massdns_path": ""
    }

    # Option descriptions
    optdescs = {
        "domainonly": "Only brute-force subdomains for the main target (non-recursive).",
        "numbermutation": "For any host found, increment/decrement existing numbers (if any) and try appending 1, 01, 001, -1, -01, -001, 2, 02, etc. (up to 10)",
        "alphamutation": "For any host found, try common mutations such as -test, -old, etc.",
        "large_wordlist": "Use a larger wordlist instead of the default ~110K. Takes roughly 20 minutes at 1000 threads.",
        "concurrent_resolvers": "Maximum concurrent lookup threads. Bandwidth cost is ~1Mbps per 100 resolvers.",
        "shuffledns_path": "Path to ShuffleDNS executable. Optional.",
        "massdns_path": "Path to MassDNS executable. Optional."
    }

    _ipRegex = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.sf.debug("Setting up sfp_tool_massdns")
        self.state = self.tempStorage()
        self.state.update({
            "sub_wordlist": [],
            "sent_events": [],
            "handled_events": []
        })
        self.__dataSource__ = "DNS"
        self.errorState = False

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

        if not self.opts["shuffledns_path"]:
            self.opts["shuffledns_path"] = which("shuffledns") or "shuffledns"
        if not self.opts["massdns_path"]:
            self.opts["massdns_path"] = which("massdns") or "massdns"

        self.word_regex = re.compile(r'[^\d\W_]+')
        self.word_num_regex = re.compile(r'[^\W_]+')
        self.num_regex = re.compile(r'\d+')

        dicts_dir = f"{self.sf.myPath()}/spiderfoot/dicts"
        if self.opts["large_wordlist"]:
            self.state["sub_wordlist"] = self.fetchLargeWordlist()
        if not self.state["sub_wordlist"] or not self.opts["large_wordlist"]:
            self.sf.debug("Using small subdomain wordlist")
            self.state["sub_wordlist"] = self.fetchSmallWordlist()
        with open(f"{dicts_dir}/subdomain-mutations.txt", "r") as f:
            if self.opts["alphamutation"]:
                self.state["alpha_mutation_wordlist"] = list(set([x.strip().lower() for x in f.readlines()]))

        # set up nameservers
        self.resolvers = self.fetchResolvers(minReliability=.99)
        self.resolvers = self.verifyNameservers(self.resolvers)
        self.sf.info(f"Using {len(self.resolvers):,} valid nameservers")

        # ensure we have resolvers
        if not self.resolvers:
            self.sf.error("No valid DNS resolvers")
            self.errorState = True

        # ensure we have valid binaries
        try:
            assert (self.opts["shuffledns_path"] and Path(self.opts["shuffledns_path"]).is_file()),\
                "Unable to find shuffledns, please set path"
            assert (self.opts["massdns_path"] and Path(self.opts["massdns_path"]).is_file()),\
                "Unable to find massdns, please set path"
        except Exception as e:
            self.sf.error(f"Error determining executable paths: {e}")
            self.errorState = True

    def watchedEvents(self):
        return ["DOMAIN_NAME", "INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]

    def producedEvents(self):
        return ["INTERNET_NAME"]

    def handleEvent(self, event):
        host = str(event.data).lower()

        if self.errorState:
            self.sf.debug(f"Module is in error state, skipping event {event.eventType} from {event.module}")
            return
        else:
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

        # if this is the main target or we're brute-forcing subdomains of subdomains
        if self.getTarget().matches(event.data, includeChildren=False) or not self.opts["domainonly"]:
            subdomains.update(set(self.state["sub_wordlist"]))

        for subdomain in self.massdns(base, subdomains):
            self.sendEvent(event, subdomain, method)

    def massdns(self, target, subdomains, concurrentResolvers=1000):
        # 1000 concurrent resolvers ~= 12Mbps up / 12Mbps down
        resolversFile = tempfile.NamedTemporaryFile(mode='w', delete=False)
        resolversFile.write('\n'.join([r.nameservers[0] for r in self.resolvers]))
        resolversFile.close()
        subdomainsFile = tempfile.NamedTemporaryFile(mode='w', delete=False)
        subdomainsFile.write('\n'.join(subdomains))
        subdomainsFile.close()

        # shuffledns is a massdns wrapper that handles subdomains and wildcards
        shufflednsCommand = (
            str(self.opts["shuffledns_path"]),
            "-nC",
            "-r", resolversFile.name,
            "-w", subdomainsFile.name,
            "-silent",
            "-t", str(concurrentResolvers),
            "-massdns", str(self.opts["massdns_path"])
        )
        self.sf.debug(f"Running ShuffleDNS: {' '.join(shufflednsCommand)}")

        try:
            p = subprocess.Popen(shufflednsCommand, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            records = p.communicate(target.encode('utf-8'))[0].decode('utf-8', errors='ignore').splitlines()
            records = list(set(records))
        finally:
            # delete temporary files
            Path(resolversFile.name).unlink()
            Path(subdomainsFile.name).unlink()

        return self.validateHosts(records)

    def sendEvent(self, source, host, method=None):
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
        self.sf.info(f"Found subdomain via {method}: {host}")
        # Report the host
        e = SpiderFootEvent("INTERNET_NAME", host, self.__name__, source)
        self.notifyListeners(e)

    def verifyNameservers(self, nameservers, timeout=2):
        """Check each resolver to make sure it can actually resolve DNS names

        Args:
            nameservers (list): nameservers to verify
            timeout (int): timeout for dns query

        Returns:
            boolean: whether any of the nameservers are valid
        """
        validResolvers = []
        with self.threadPool(threads=100, name='sfp_tool_massdns_verify_nameservers') as pool:
            for resolver, error in pool.map(nameservers, self.verifyNameserver):
                if not error:
                    validResolvers.append(resolver)
                else:
                    self.sf.debug(str(error))
        return validResolvers

    def verifyNameserver(self, nameserver, timeout=2):
        """Validate a nameserver by making a sample query and a garbage query

        Args:
            nameserver (str): nameserver to verify
            timeout (int): timeout for dns query

        Returns:
            boolean: whether the nameserver is valid
        """
        error = None

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.nameservers = [nameserver]

        # first, make sure it can resolve google.com
        try:
            resolver.resolve("www.google.com", "A")
        except Exception:
            error = f"Nameserver {nameserver} failed to resolve basic query within {timeout} seconds."

        # then, make sure it isn't feeding us garbage data
        randpool = "bcdfghjklmnpqrstvwxyz3456789"
        randhost = "".join([random.SystemRandom().choice(randpool) for x in range(10)]) + ".google.com"
        try:
            results = list(resolver.resolve(randhost, "A"))
            if results:
                error = f"Nameserver {nameserver} returned garbage data."
        except Exception:
            # Garbage query to nameserver failed successfully ;)
            pass

        return resolver, error

    def validateHosts(self, hosts):

        hosts = [h for h in hosts if h not in self.state["sent_events"]]
        validHosts = []
        with self.threadPool(threads=100, name='sfp_tool_massdns_validate_hosts') as pool:
            for h, valid in pool.map(hosts, self.isValidHost):
                if valid:
                    validHosts.append(h)
                else:
                    self.sf.debug(f"Incorrectly-reported subdomain {h} does not exist.")
        return validHosts

    def isValidHost(self, host):
        """Verify that the record is valid, not a duplicate, and not resulting from wildcard DNS

        Args:
            host (str): host to validate

        Returns:
            boolean: whether the record is valid
        """

        # make double-sure that this host actually exists
        ips_google = self.resolve(host, nameserver="8.8.8.8")[1]
        ips_cloudflare = self.resolve(host, nameserver="1.1.1.1")[1]
        if not ips_google or not ips_cloudflare:
            return (host, False)
        return (host, True)

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
        with suppress(KeyError):
            subdomains.remove(host)

        return subdomains

    def getAlphaMutations(self, host):
        subdomains = set()
        host, domain = host.split(".", 1)

        # if the input is "host01-www", it tries "host01", "host", and "www"
        for m in list(self.word_regex.findall(host)) + list(self.word_num_regex.findall(host)):
            if m != host:
                subdomains.add(m)
            if m not in self.state["alpha_mutation_wordlist"]:
                self.state["alpha_mutation_wordlist"].append(m)
        # if the input is "host01-www", it tries "host01-<mutation>", "<mutation>01-www", and "<mutation>-www"
        for match in list(self.word_regex.finditer(host))[-3:] + list(self.word_num_regex.finditer(host))[-3:]:
            span = match.span()
            before = host[:span[0]]
            after = host[span[-1]:]
            for m in self.state["alpha_mutation_wordlist"]:
                subdomains.add(before + m + after)

        # if the input is "host01-www", it tries "host01-www-<mutation>", "<mutation>-host01-www", etc.
        for m in self.state["alpha_mutation_wordlist"]:
            subdomains.add(f"{host}.{m}")
            subdomains.add(f"{host}-{m}")
            subdomains.add(f"{m}{host}")
            subdomains.add(f"{m}-{host}")
            subdomains.add(f"{m}.{host}")

        # ensure we aren't including the source subdomain
        with suppress(KeyError):
            subdomains.remove(host)

        return subdomains

    def fetchResolvers(self, minReliability):
        resolverlist = self.sf.cacheGet("resolverlist", 72)
        if resolverlist is not None:
            nameservers = self._ipRegex.findall(resolverlist)
            self.sf.debug(f"Loaded {len(nameservers):,} nameservers from cache")
        else:
            nameservers = set()
            nameservers_url = "https://public-dns.info/nameserver/nameservers.json"
            # get every valid nameserver
            try:
                for entry in json.loads(self.sf.fetchUrl(
                    nameservers_url,
                    useragent=self.opts.get("_useragent", "Spiderfoot")
                )["content"]):
                    ip_address = str(entry.get("ip", "")).strip()
                    try:
                        reliability = float(entry.get("reliability", 0))
                    except ValueError:
                        continue
                    if reliability >= minReliability and self._ipRegex.match(ip_address):
                        nameservers.add(ip_address)
            except ValueError as e:
                self.sf.debug(f"Failed to fetch nameservers from public-dns.info: {e}")
                pass
            self.sf.debug(f"Loaded {len(nameservers):,} nameservers from {nameservers_url}")
            self.sf.cachePut("resolverlist", list(nameservers))
        return nameservers

    def fetchSmallWordlist(self):
        subdomains = []
        subdomainsList = self.sf.cacheGet("massdns_subdomains_small", 672)

        if subdomainsList is not None:
            subdomains = subdomainsList.splitlines()
            self.sf.debug(f"Loaded small subdomain wordlist ({len(subdomains):,} entries) from cache")
        else:
            wordlist_url = "https://github.com/danielmiessler/SecLists/raw/master/Discovery/DNS/subdomains-top1million-110000.txt"
            self.sf.debug(f"Fetching small subdomain wordlist from {wordlist_url}")
            response = self.sf.fetchUrl(
                wordlist_url,
                useragent=self.opts.get("_useragent", "Spiderfoot")
            )
            if response.get("code", None) == "200":
                wordlist = response["content"]
                if wordlist:
                    subdomains = wordlist.splitlines()
                    self.sf.debug(f"Fetched small subdomain wordlist ({len(subdomains):,} entries) from {wordlist_url}")
            if subdomains:
                self.sf.cachePut("massdns_subdomains_small", subdomains)
            else:
                self.sf.debug(f"Failed to fetch small wordlist from {wordlist_url}, falling back to local copy")
                filename = f"{self.sf.myPath()}/spiderfoot/dicts/massdns-subdomains-110K.txt"
                with open(filename) as f:
                    subdomains = f.readlines()
                self.sf.debug(f"Loaded small subdomain wordlist ({len(subdomains):,} entries) from local copy")

        return subdomains

    def fetchLargeWordlist(self):
        subdomains = []
        subdomainsList = self.sf.cacheGet("massdns_subdomains_large", 672)

        if subdomainsList is not None:
            subdomains = subdomainsList.splitlines()
            self.sf.debug(f"Loaded large subdomain wordlist ({len(subdomains):,} entries) from cache")
        else:
            today = datetime.datetime.now()
            day = 28
            month = int(today.month)
            year = int(today.year)

            for _ in range(12):
                filename = f"httparchive_subdomains_{year:02d}_{month:02d}_{day:02d}.txt"
                wordlist_url = f"https://wordlists-cdn.assetnote.io/data/automated/{filename}"
                self.sf.debug(f"Fetching large subdomain wordlist from {wordlist_url}")
                response = self.sf.fetchUrl(
                    wordlist_url,
                    useragent=self.opts.get("_useragent", "Spiderfoot")
                )
                if response.get("code", None) == "200":
                    wordlist = response.get("content", None)
                    break
                else:
                    self.sf.debug(f"Wordlist not found at {wordlist_url}")
                    month -= 1
                    if month < 0:
                        year -= 1
                        month = 12
            if not wordlist:
                self.sf.debug("Failed to fetch large subdomain wordlist from assetnote.io")
            else:
                subdomains = wordlist.splitlines()
                self.sf.debug(f"Fetched large subdomain wordlist ({len(subdomains):,} entries) from {wordlist_url}")
            if subdomains:
                self.sf.cachePut("massdns_subdomains_large", subdomains)

        return subdomains

    def resolve(self, host, tries=10, nameserver=None):
        if nameserver is None:
            nameserver = "8.8.8.8"
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
