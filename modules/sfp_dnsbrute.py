# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_dnsbrute
# Purpose:      SpiderFoot plug-in for attempting to resolve through brute-forcing
#               common hostnames.
#
# Author:      TheTechromancer
#
# Created:     05/19/2021
# Licence:     GPL
# -------------------------------------------------------------------------------


import re
import random
import threading
import dns.resolver
from time import sleep
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
        "commons": True,
        "top10000": False,
        "numbersuffix": True,
        "alphamutation": True,
        "_maxthreads": 100
    }

    # Option descriptions
    optdescs = {
        "domainonly": "Only attempt to brute-force names on domain names, not hostnames (some hostnames are also sub-domains).",
        "commons": "Try a list of about 750 common hostnames/sub-domains.",
        "top10000": "Try a further 10,000 common hostnames/sub-domains. Will make the scan much slower.",
        "numbersuffix": "For any host found, try appending 1, 01, 001, -1, -01, -001, 2, 02, etc. (up to 10)",
        "alphamutation": "For any host found, try common mutations such as -test, -old, etc.",
        "_maxthreads": "Maximum threads"
    }

    def setup(self, sfc, userOpts=dict()):

        self.sf = sfc
        self.sf.debug("Setting up sfp_dnsbrute")
        self.state = self.tempStorage()
        self.state.update({
            "sub_wordlist": [],
            "valid_hosts": [],
            "events": [],
            "wildcards": dict()
        })
        self.__dataSource__ = "DNS"
        self.lock = threading.Lock()
        self.iteration = 0

        self.opts.update(userOpts)

        if self.opts["top10000"]:
            with open(self.sf.myPath() + "/dicts/subdomains-10000.txt", "r") as f:
                self.state["sub_wordlist"] = list(set([x.strip().lower() for x in f.readlines()]))
        elif self.opts["commons"]:
            with open(self.sf.myPath() + "/dicts/subdomains.txt", "r") as f:
                self.state["sub_wordlist"] = list(set([x.strip().lower() for x in f.readlines()]))
        with open(self.sf.myPath() + "/dicts/subdomain_mutations_alpha.txt", "r") as f:
            if self.opts["alphamutation"]:
                self.state["alpha_mutation_wordlist"] = list(set([x.strip().lower() for x in f.readlines()]))

        self.resolvers = []
        nameservers = list(set([x.strip().lower() for x in open(self.sf.myPath() + "/dicts/resolvers.txt", "r").readlines()]))
        self.verifyNameservers(nameservers)
        #self.verifyNameservers(["8.8.8.8"])


    def resolve(self, host, tries=10, nameserver=None):

        if nameserver is None:
            resolver = self.getResolver()
        else:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [nameserver]

        self.sf.debug(f"resolving {host} using nameserver {resolver.nameservers[0]}")

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
                    return self.resolve(host, tries=tries-1)
                else:
                    self.sf.debug(f"Max retries ({tries:,}) exceeded for \"{host}\"")
                    return (host,[])

        return (host, list(ips))


    def isWildcard(self, target, ips):
        """
        Checks if a target resulted from a wildcard DNS configuration
        Note: allows the first result through, so one entry is preserved
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
        """
        Check each resolver to make sure it can actually resolve DNS names
        """

        for nameserver in nameservers:
            threading.Thread(name=f"sfp_dnsbrute_{nameserver}", target=self.verifyNameserver, args=(nameserver,timeout)).start()
        sleep(timeout)
        if len(self.resolvers) > 0:
            self.sf.debug(f"Using {len(self.resolvers):,} valid nameservers")
            return True
        else:
            return False


    def verifyNameserver(self, nameserver, timeout=2):
        """
        Tests to make sure a nameserver is functional by resolving www.google.com with a 2-second timeout
        """

        valid = True

        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.nameservers = [nameserver]

        # first, make sure it can resolve google.com
        try:
            resolver.query("www.google.com", "A")
        except:
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


    def watchedEvents(self):
        """
        Event types this modules consumes
        """
        ret = ["DOMAIN_NAME"]
        if not self.opts["domainonly"] or self.opts["numbersuffix"] or self.opts["alphamutation"]:
            ret += ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"]
        return ret


    def producedEvents(self):
        """
        Event types this module produces
        """
        return ["INTERNET_NAME"]


    def isValidHost(self, host, ips):
        """
        Verify that the host is valid, not a duplicate, and not resulting from wildcard DNS
        """

        # make double-sure that this host actually exists
        ips_google = self.resolve(host, nameserver="8.8.8.8")[1]
        ips_cloudflare = self.resolve(host, nameserver="1.1.1.1")[1]
        if not ips_google or not ips_cloudflare:
            self.sf.debug(f"Incorrectly-reported subdomain: {host}")
            return False

        # if we haven't seen the host before
        if not host in self.state["valid_hosts"]:
            # and it isn"t a wildcard
            if not self.isWildcard(host, ips):
                return True
            else:
                self.sf.debug(f"Invalid wildcard host: {host}")
        else:
            self.sf.debug(f"Already processed host: {host}")

        return False


    def sendEvent(self, source, host, ips, method=None):
        """
        Store the result internally and notify listening modules
        """

        if method is None:
            method = ""

        host = host.lower()
        if ips and self.isValidHost(host, ips):
            self.state["valid_hosts"].append(host)
            self.sf.info(f"Found subdomain via {method}: {host}")
            # Report the host
            e = SpiderFootEvent("INTERNET_NAME", host, self.__name__, source)
            self.notifyListeners(e)

    
    def brute_alphamutation(self, host):

        with self.threadPool(threads=self.opts["_maxthreads"], name='sfp_dnsbrute_alphamutation') as pool:
            for new_host,ips in pool.map(
                    self.get_alphamutation(host),
                    self.resolve
                ):
                if ips:
                    yield (new_host, ips)
      

    def brute_numbersuffix(self, host, num=10):

        with self.threadPool(threads=self.opts["_maxthreads"], name='sfp_dnsbrute_numbersuffix') as pool:
            for new_host,ips in pool.map(
                    self.get_numbersuffixes(host, num=num),
                    self.resolve
                ):
                if ips:
                    yield (new_host, ips)


    def get_numbersuffixes(self, host, num=10):

        host, domain = host.split(".", 1)
        for a in ["", "0", "00", "-", "-0", "-00"]:
            for i in range(num):
                yield f"{host}{a}{i}.{domain}"


    def get_alphamutation(self, host):

        host, domain = host.split(".", 1)

        for m in self.state["alpha_mutation_wordlist"]:
            yield f"{host}{m}.{domain}"
            yield f"{host}-{m}.{domain}"
            yield f"{m}{host}.{domain}"
            yield f"{m}-{host}.{domain}"


    def brute_subdomains(self, host):

        self.sf.debug("Iterating through possible subdomains.")

        with self.threadPool(threads=self.opts["_maxthreads"], name='sfp_dnsbrute_subdomains') as pool:
            for hostname,ips in pool.map(
                    [f"{sub}.{host}" for sub in self.state["sub_wordlist"]],
                    self.resolve, 
                ):
                if ips:
                    yield (hostname, ips)


    def handleEvent(self, event):
        """
        Handle events sent to this module
        """

        if not self.resolvers:
            self.sf.error("No valid DNS resolvers")
            return

        host = str(event.data).lower()

        self.sf.debug(f"Received event, {event.eventType}, from {event.module}")

        # skip if we've already processed this event
        eventDataHash = self.sf.hashstring(event.data)
        if eventDataHash in self.state["events"]:
            self.sf.debug(f"Skipping already-processed event, {event.eventType}, from {event.module}")
            return
        self.state["events"].append(eventDataHash)

        # if this isn't the main target, we can still do numeric suffixes
        if event.eventType in ["INTERNET_NAME", "INTERNET_NAME_UNRESOLVED"] and not self.getTarget().matches(event.data, includeChildren=False):
            if self.opts["numbersuffix"]:
                for hostname,ips in self.brute_numbersuffix(host):
                    self.sendEvent(event, hostname, ips, "number suffix brute")

            if self.opts["alphamutation"]:
                for hostname,ips in self.brute_alphamutation(host):
                    self.sendEvent(event, hostname, ips, "alpha mutation brute")


        # if this is the main target or we're brute-forcing subdomains of subdomains
        if self.getTarget().matches(event.data, includeChildren=False) or not self.opts["domainonly"]:

            # subdomain brute force
            for hostname,ips in self.brute_subdomains(host):
                self.sendEvent(event, hostname, ips, "subdomain brute")