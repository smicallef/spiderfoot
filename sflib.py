#  -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sflib
# Purpose:      Common functions used by SpiderFoot modules.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     26/03/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     GPL
# -------------------------------------------------------------------------------

import hashlib
import html
import inspect
import io
import json
import logging
import os
import random
import re
import socket
import ssl
import sys
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from copy import deepcopy
from datetime import datetime

import cryptography
import dns.resolver
import netaddr
import phonenumbers
import OpenSSL
import requests
import urllib3
from bs4 import BeautifulSoup, SoupStrainer
from publicsuffixlist import PublicSuffixList
from spiderfoot import SpiderFootHelpers

# For hiding the SSL warnings coming from the requests lib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # noqa: DUO131


class SpiderFoot:
    """SpiderFoot

    Attributes:
        dbh (SpiderFootDb): database handle
        scanId (str): scan ID this instance of SpiderFoot is being used in
        socksProxy (str): SOCKS proxy
        opts (dict): configuration options
    """
    _dbh = None
    _scanId = None
    _socksProxy = None
    opts = dict()

    def __init__(self, options: dict) -> None:
        """Initialize SpiderFoot object.

        Args:
            options (dict): dictionary of configuration options.

        Raises:
            TypeError: options argument was invalid type
        """
        if not isinstance(options, dict):
            raise TypeError("options is %s; expected dict()" % type(options))

        self.opts = deepcopy(options)
        self.log = logging.getLogger(f"spiderfoot.{__name__}")

        # This is ugly but we don't want any fetches to fail - we expect
        # to encounter unverified SSL certs!
        ssl._create_default_https_context = ssl._create_unverified_context  # noqa: DUO122

        if self.opts.get('_dnsserver', "") != "":
            res = dns.resolver.Resolver()
            res.nameservers = [self.opts['_dnsserver']]
            dns.resolver.override_system_resolver(res)

    @property
    def dbh(self):
        """Database handle

        Returns:
            SpiderFootDb: database handle
        """
        return self._dbh

    @property
    def scanId(self) -> str:
        """Scan instance ID

        Returns:
            str: scan instance ID
        """
        return self._scanId

    @property
    def socksProxy(self) -> str:
        """SOCKS proxy

        Returns:
            str: socks proxy
        """
        return self._socksProxy

    @dbh.setter
    def dbh(self, dbh):
        """Called usually some time after instantiation
        to set up a database handle and scan ID, used
        for logging events to the database about a scan.

        Args:
            dbh (SpiderFootDB): database handle
        """
        self._dbh = dbh

    @scanId.setter
    def scanId(self, scanId: str) -> str:
        """Set the scan ID this instance of SpiderFoot is being used in.

        Args:
            scanId (str): scan instance ID
        """
        self._scanId = scanId

    @socksProxy.setter
    def socksProxy(self, socksProxy: str) -> str:
        """SOCKS proxy

        Bit of a hack to support SOCKS because of the loading order of
        modules. sfscan will call this to update the socket reference
        to the SOCKS one.

        Args:
            socksProxy (str): SOCKS proxy
        """
        self._socksProxy = socksProxy

    def optValueToData(self, val: str) -> str:
        """Supplied an option value, return the data based on what the
        value is. If val is a URL, you'll get back the fetched content,
        if val is a file path it will be loaded and get back the contents,
        and if a string it will simply be returned back.

        Args:
            val (str): option name

        Returns:
            str: option data
        """
        if not isinstance(val, str):
            self.error(f"Invalid option value {val}")
            return None

        if val.startswith('@'):
            fname = val.split('@')[1]
            self.info(f"Loading configuration data from: {fname}")

            try:
                with open(fname, "r") as f:
                    return f.read()
            except Exception as e:
                self.error(f"Unable to open option file, {fname}: {e}")
                return None

        if val.lower().startswith('http://') or val.lower().startswith('https://'):
            try:
                self.info(f"Downloading configuration data from: {val}")
                session = self.getSession()
                res = session.get(val)

                return res.content.decode('utf-8')
            except BaseException as e:
                self.error(f"Unable to open option URL, {val}: {e}")
                return None

        return val

    def error(self, message: str) -> None:
        """Print and log an error message

        Args:
            message (str): error message
        """
        if not self.opts['__logging']:
            return

        self.log.error(message, extra={'scanId': self._scanId})

    def fatal(self, error: str) -> None:
        """Print an error message and stacktrace then exit.

        Args:
            error (str): error message
        """
        self.log.critical(error, extra={'scanId': self._scanId})

        print(str(inspect.stack()))

        sys.exit(-1)

    def status(self, message: str) -> None:
        """Log and print a status message.

        Args:
            message (str): status message
        """
        if not self.opts['__logging']:
            return

        self.log.info(message, extra={'scanId': self._scanId})

    def info(self, message: str) -> None:
        """Log and print an info message.

        Args:
            message (str): info message
        """
        if not self.opts['__logging']:
            return

        self.log.info(f"{message}", extra={'scanId': self._scanId})

    def debug(self, message: str) -> None:
        """Log and print a debug message.

        Args:
            message (str): debug message
        """
        if not self.opts['_debug']:
            return
        if not self.opts['__logging']:
            return

        self.log.debug(f"{message}", extra={'scanId': self._scanId})

    @staticmethod
    def myPath() -> str:
        """This will get us the program's directory, even if we are frozen using py2exe.

        Returns:
            str: Program root directory
        """
        # Determine whether we've been compiled by py2exe
        if hasattr(sys, "frozen"):
            return os.path.dirname(sys.executable)

        return os.path.dirname(__file__)

    def hashstring(self, string: str) -> str:
        """Returns a SHA256 hash of the specified input.

        Args:
            string (str): data to be hashed

        Returns:
            str: SHA256 hash
        """
        s = string
        if type(string) in [list, dict]:
            s = str(string)
        return hashlib.sha256(s.encode('raw_unicode_escape')).hexdigest()

    def cachePut(self, label: str, data: str) -> None:
        """Store data to the cache

        Args:
            label (str): Name of the cached data to be used when retrieving the cached data.
            data (str): Data to cache
        """
        pathLabel = hashlib.sha224(label.encode('utf-8')).hexdigest()
        cacheFile = SpiderFootHelpers.cachePath() + "/" + pathLabel
        with io.open(cacheFile, "w", encoding="utf-8", errors="ignore") as fp:
            if isinstance(data, list):
                for line in data:
                    if isinstance(line, str):
                        fp.write(line)
                        fp.write("\n")
                    else:
                        fp.write(line.decode('utf-8') + '\n')
            elif isinstance(data, bytes):
                fp.write(data.decode('utf-8'))
            else:
                fp.write(data)

    def cacheGet(self, label: str, timeoutHrs: int) -> str:
        """Retreive data from the cache

        Args:
            label (str): Name of the cached data to retrieve
            timeoutHrs (int): Age of the cached data (in hours)
                              for which the data is considered to be too old and ignored.

        Returns:
            str: cached data
        """
        if label is None:
            return None

        pathLabel = hashlib.sha224(label.encode('utf-8')).hexdigest()
        cacheFile = SpiderFootHelpers.cachePath() + "/" + pathLabel
        try:
            (m, i, d, n, u, g, sz, atime, mtime, ctime) = os.stat(cacheFile)

            if sz == 0:
                return None

            if mtime > time.time() - timeoutHrs * 3600 or timeoutHrs == 0:
                with open(cacheFile, "r") as fp:
                    return fp.read()
        except BaseException:
            return None

        return None

    def configSerialize(self, opts: dict, filterSystem: bool = True):
        """Convert a Python dictionary to something storable in the database.

        Args:
            opts (dict): Dictionary of SpiderFoot configuration options
            filterSystem (bool): TBD

        Returns:
            dict: config options

        Raises:
            TypeError: arg type was invalid
        """
        if not isinstance(opts, dict):
            raise TypeError("opts is %s; expected dict()" % type(opts))

        storeopts = dict()

        if not opts:
            return storeopts

        for opt in list(opts.keys()):
            # Filter out system temporary variables like GUID and others
            if opt.startswith('__') and filterSystem:
                continue

            if isinstance(opts[opt], (int, str)):
                storeopts[opt] = opts[opt]

            if isinstance(opts[opt], bool):
                if opts[opt]:
                    storeopts[opt] = 1
                else:
                    storeopts[opt] = 0
            if isinstance(opts[opt], list):
                storeopts[opt] = ','.join(opts[opt])

        if '__modules__' not in opts:
            return storeopts

        if not isinstance(opts['__modules__'], dict):
            raise TypeError("opts['__modules__'] is %s; expected dict()" % type(opts['__modules__']))

        for mod in opts['__modules__']:
            for opt in opts['__modules__'][mod]['opts']:
                if opt.startswith('_') and filterSystem:
                    continue

                mod_opt = f"{mod}:{opt}"
                mod_opt_val = opts['__modules__'][mod]['opts'][opt]

                if isinstance(mod_opt_val, (int, str)):
                    storeopts[mod_opt] = mod_opt_val

                if isinstance(mod_opt_val, bool):
                    if mod_opt_val:
                        storeopts[mod_opt] = 1
                    else:
                        storeopts[mod_opt] = 0
                if isinstance(mod_opt_val, list):
                    storeopts[mod_opt] = ','.join(str(x) for x in mod_opt_val)

        return storeopts

    def configUnserialize(self, opts: dict, referencePoint: dict, filterSystem: bool = True):
        """Take strings, etc. from the database or UI and convert them
        to a dictionary for Python to process.

        Args:
            opts (dict): SpiderFoot configuration options
            referencePoint (dict): needed to know the actual types the options are supposed to be.
            filterSystem (bool): Ignore global "system" configuration options

        Returns:
            dict: TBD

        Raises:
            TypeError: arg type was invalid
        """

        if not isinstance(opts, dict):
            raise TypeError("opts is %s; expected dict()" % type(opts))
        if not isinstance(referencePoint, dict):
            raise TypeError("referencePoint is %s; expected dict()" % type(referencePoint))

        returnOpts = referencePoint

        # Global options
        for opt in list(referencePoint.keys()):
            if opt.startswith('__') and filterSystem:
                # Leave out system variables
                continue

            if opt not in opts:
                continue

            if isinstance(referencePoint[opt], bool):
                if opts[opt] == "1":
                    returnOpts[opt] = True
                else:
                    returnOpts[opt] = False
                continue

            if isinstance(referencePoint[opt], str):
                returnOpts[opt] = str(opts[opt])
                continue

            if isinstance(referencePoint[opt], int):
                returnOpts[opt] = int(opts[opt])
                continue

            if isinstance(referencePoint[opt], list):
                if isinstance(referencePoint[opt][0], int):
                    returnOpts[opt] = list()
                    for x in str(opts[opt]).split(","):
                        returnOpts[opt].append(int(x))
                else:
                    returnOpts[opt] = str(opts[opt]).split(",")

        if '__modules__' not in referencePoint:
            return returnOpts

        if not isinstance(referencePoint['__modules__'], dict):
            raise TypeError("referencePoint['__modules__'] is %s; expected dict()" % type(referencePoint['__modules__']))

        # Module options
        # A lot of mess to handle typing..
        for modName in referencePoint['__modules__']:
            for opt in referencePoint['__modules__'][modName]['opts']:
                if opt.startswith('_') and filterSystem:
                    continue

                if modName + ":" + opt in opts:
                    ref_mod = referencePoint['__modules__'][modName]['opts'][opt]
                    if isinstance(ref_mod, bool):
                        if opts[modName + ":" + opt] == "1":
                            returnOpts['__modules__'][modName]['opts'][opt] = True
                        else:
                            returnOpts['__modules__'][modName]['opts'][opt] = False
                        continue

                    if isinstance(ref_mod, str):
                        returnOpts['__modules__'][modName]['opts'][opt] = str(opts[modName + ":" + opt])
                        continue

                    if isinstance(ref_mod, int):
                        returnOpts['__modules__'][modName]['opts'][opt] = int(opts[modName + ":" + opt])
                        continue

                    if isinstance(ref_mod, list):
                        if isinstance(ref_mod[0], int):
                            returnOpts['__modules__'][modName]['opts'][opt] = list()
                            for x in str(opts[modName + ":" + opt]).split(","):
                                returnOpts['__modules__'][modName]['opts'][opt].append(int(x))
                        else:
                            returnOpts['__modules__'][modName]['opts'][opt] = str(opts[modName + ":" + opt]).split(",")

        return returnOpts

    def modulesProducing(self, events: list) -> list:
        """Return an array of modules that produce the list of types supplied.

        Args:
            events (list): list of event types

        Returns:
            list: list of modules
        """
        modlist = list()

        if not events:
            return modlist

        loaded_modules = self.opts.get('__modules__')

        if not loaded_modules:
            return modlist

        for mod in list(loaded_modules.keys()):
            provides = loaded_modules[mod].get('provides')

            if not provides:
                continue

            if "*" in events:
                modlist.append(mod)

            for evtype in provides:
                if evtype in events:
                    modlist.append(mod)

        return list(set(modlist))

    def modulesConsuming(self, events: list) -> list:
        """Return an array of modules that consume the list of types supplied.

        Args:
            events (list): list of event types

        Returns:
            list: list of modules
        """
        modlist = list()

        if not events:
            return modlist

        loaded_modules = self.opts.get('__modules__')

        if not loaded_modules:
            return modlist

        for mod in list(loaded_modules.keys()):
            consumes = loaded_modules[mod].get('consumes')

            if not consumes:
                continue

            if "*" in consumes:
                modlist.append(mod)
                continue

            for evtype in consumes:
                if evtype in events:
                    modlist.append(mod)

        return list(set(modlist))

    def eventsFromModules(self, modules: list) -> list:
        """Return an array of types that are produced by the list of modules supplied.

        Args:
            modules (list): list of modules

        Returns:
            list: list of types
        """
        evtlist = list()

        if not modules:
            return evtlist

        loaded_modules = self.opts.get('__modules__')

        if not loaded_modules:
            return evtlist

        for mod in modules:
            if mod in list(loaded_modules.keys()):
                provides = loaded_modules[mod].get('provides')
                if provides:
                    for evt in provides:
                        evtlist.append(evt)

        return evtlist

    def eventsToModules(self, modules: list) -> list:
        """Return an array of types that are consumed by the list of modules supplied.

        Args:
            modules (list): list of modules

        Returns:
            list: list of types
        """
        evtlist = list()

        if not modules:
            return evtlist

        loaded_modules = self.opts.get('__modules__')

        if not loaded_modules:
            return evtlist

        for mod in modules:
            if mod in list(loaded_modules.keys()):
                consumes = loaded_modules[mod].get('consumes')
                if consumes:
                    for evt in consumes:
                        evtlist.append(evt)

        return evtlist

    def urlRelativeToAbsolute(self, url: str) -> str:
        """Turn a relative path into an absolute path

        Args:
            url (str): URL

        Returns:
            str: URL relative path
        """
        if not url:
            self.error("Invalid URL: %s" % url)
            return None

        finalBits = list()

        if '..' not in url:
            return url

        bits = url.split('/')

        for chunk in bits:
            if chunk == '..':
                # Don't pop the last item off if we're at the top
                if len(finalBits) <= 1:
                    continue

                # Don't pop the last item off if the first bits are not the path
                if '://' in url and len(finalBits) <= 3:
                    continue

                finalBits.pop()
                continue

            finalBits.append(chunk)

        return '/'.join(finalBits)

    def urlBaseDir(self, url: str) -> str:
        """Extract the top level directory from a URL

        Args:
            url (str): URL

        Returns:
            str: base directory
        """
        if not url:
            self.error("Invalid URL: %s" % url)
            return None

        bits = url.split('/')

        # For cases like 'www.somesite.com'
        if len(bits) == 0:
            return url + '/'

        # For cases like 'http://www.blah.com'
        if '://' in url and url.count('/') < 3:
            return url + '/'

        base = '/'.join(bits[:-1])

        return base + '/'

    def urlBaseUrl(self, url: str) -> str:
        """Extract the scheme and domain from a URL

        Does not return the trailing slash! So you can do .endswith() checks.

        Args:
            url (str): URL

        Returns:
            str: base URL without trailing slash
        """
        if not url:
            self.error("Invalid URL: %s" % url)
            return None

        if '://' in url:
            bits = re.match(r'(\w+://.[^/:\?]*)[:/\?].*', url)
        else:
            bits = re.match(r'(.[^/:\?]*)[:/\?]', url)

        if bits is None:
            return url.lower()

        return bits.group(1).lower()

    def urlFQDN(self, url: str) -> str:
        """Extract the FQDN from a URL.

        Args:
            url (str): URL

        Returns:
            str: FQDN
        """
        if not url:
            self.error(f"Invalid URL: {url}")
            return None

        baseurl = self.urlBaseUrl(url)
        if '://' in baseurl:
            count = 2
        else:
            count = 0

        # http://abc.com will split to ['http:', '', 'abc.com']
        return baseurl.split('/')[count].lower()

    def domainKeyword(self, domain: str, tldList: list) -> str:
        """Extract the keyword (the domain without the TLD or any subdomains) from a domain.

        Args:
            domain (str): The domain to check.
            tldList (list): The list of TLDs based on the Mozilla public list.

        Returns:
            str: The keyword
        """
        if not domain:
            self.error(f"Invalid domain: {domain}")
            return None

        # Strip off the TLD
        dom = self.hostDomain(domain.lower(), tldList)
        if not dom:
            return None

        tld = '.'.join(dom.split('.')[1:])
        ret = domain.lower().replace('.' + tld, '')

        # If the user supplied a domain with a sub-domain, return the second part
        if '.' in ret:
            return ret.split('.')[-1]

        return ret

    def domainKeywords(self, domainList: list, tldList: list) -> set:
        """Extract the keywords (the domains without the TLD or any subdomains) from a list of domains.

        Args:
            domainList (list): The list of domains to check.
            tldList (list): The list of TLDs based on the Mozilla public list.

        Returns:
            set: List of keywords
        """
        if not domainList:
            self.error("Invalid domain list: %s" % domainList)
            return set()

        keywords = list()
        for domain in domainList:
            keywords.append(self.domainKeyword(domain, tldList))

        self.debug("Keywords: %s" % keywords)
        return set([k for k in keywords if k])

    def hostDomain(self, hostname: str, tldList: list) -> str:
        """Obtain the domain name for a supplied hostname.

        Args:
            hostname (str): The hostname to check.
            tldList (list): The list of TLDs based on the Mozilla public list.

        Returns:
            str: The domain name.
        """
        if not tldList:
            return None
        if not hostname:
            return None

        ps = PublicSuffixList(tldList, only_icann=True)
        return ps.privatesuffix(hostname)

    def validHost(self, hostname: str, tldList: str) -> bool:
        """Check if the provided string is a valid hostname with a valid public suffix TLD.

        Args:
            hostname (str): The hostname to check.
            tldList (str): The list of TLDs based on the Mozilla public list.

        Returns:
            bool
        """
        if not tldList:
            return False
        if not hostname:
            return False

        if "." not in hostname:
            return False

        if not re.match(r"^[a-z0-9-\.]*$", hostname, re.IGNORECASE):
            return False

        ps = PublicSuffixList(tldList, only_icann=True, accept_unknown=False)
        sfx = ps.privatesuffix(hostname)
        return sfx is not None

    def isDomain(self, hostname: str, tldList: list) -> bool:
        """Check if the provided hostname string is a valid domain name.

        Given a possible hostname, check if it's a domain name
        By checking whether it rests atop a valid TLD.
        e.g. www.example.com = False because tld of hostname is com,
        and www.example has a . in it.

        Args:
            hostname (str): The hostname to check.
            tldList (list): The list of TLDs based on the Mozilla public list.

        Returns:
            bool
        """
        if not tldList:
            return False
        if not hostname:
            return False

        ps = PublicSuffixList(tldList, only_icann=True, accept_unknown=False)
        sfx = ps.privatesuffix(hostname)
        return sfx == hostname

    def validIP(self, address: str) -> bool:
        """Check if the provided string is a valid IPv4 address.

        Args:
            address (str): The IPv4 address to check.

        Returns:
            bool
        """
        if not address:
            return False
        return netaddr.valid_ipv4(address)

    def validIP6(self, address: str) -> bool:
        """Check if the provided string is a valid IPv6 address.

        Args:
            address (str): The IPv6 address to check.

        Returns:
            bool: string is a valid IPv6 address
        """
        if not address:
            return False
        return netaddr.valid_ipv6(address)

    def validIpNetwork(self, cidr: str) -> bool:
        """Check if the provided string is a valid CIDR netblock.

        Args:
            cidr (str): The netblock to check.

        Returns:
            bool: string is a valid CIDR netblock
        """
        if not isinstance(cidr, str):
            return False

        if '/' not in cidr:
            return False

        try:
            return bool(netaddr.IPNetwork(str(cidr)).size > 0)
        except BaseException:
            return False

    def isPublicIpAddress(self, ip: str) -> bool:
        """Check if an IP address is public.

        Args:
            ip (str): IP address

        Returns:
            bool: IP address is public
        """
        if not isinstance(ip, (str, netaddr.IPAddress)):
            return False
        if not self.validIP(ip) and not self.validIP6(ip):
            return False

        if not netaddr.IPAddress(ip).is_unicast():
            return False

        if netaddr.IPAddress(ip).is_loopback():
            return False
        if netaddr.IPAddress(ip).is_reserved():
            return False
        if netaddr.IPAddress(ip).is_multicast():
            return False
        if netaddr.IPAddress(ip).is_private():
            return False
        return True

    def normalizeDNS(self, res: list) -> list:
        """Clean DNS results to be a simple list

        Args:
            res (list): List of DNS names

        Returns:
            list: list of domains
        """
        ret = list()

        if not res:
            return ret

        for addr in res:
            if isinstance(addr, list):
                for host in addr:
                    host = str(host).rstrip(".")
                    if host:
                        ret.append(host)
            else:
                host = str(addr).rstrip(".")
                if host:
                    ret.append(host)
        return ret

    def validEmail(self, email: str) -> bool:
        """Check if the provided string is a valid email address.

        Args:
            email (str): The email address to check.

        Returns:
            bool: email is a valid email address
        """
        if not isinstance(email, str):
            return False

        if "@" not in email:
            return False

        if not re.match(r'^([\%a-zA-Z\.0-9_\-\+]+@[a-zA-Z\.0-9\-]+\.[a-zA-Z\.0-9\-]+)$', email):
            return False

        if len(email) < 6:
            return False

        # Skip strings with messed up URL encoding
        if "%" in email:
            return False

        # Skip strings which may have been truncated
        if "..." in email:
            return False

        return True

    def validPhoneNumber(self, phone: str) -> bool:
        """Check if the provided string is a valid phone number.

        Args:
            phone (str): The phone number to check.

        Returns:
            bool: string is a valid phone number
        """
        if not isinstance(phone, str):
            return False

        try:
            return phonenumbers.is_valid_number(phonenumbers.parse(phone))
        except Exception:
            return False

    def dictwords(self) -> list:
        """Return dictionary words and/or names from several language dictionaries.

        Returns:
            list: words and names from dictionaries
        """
        wd = dict()

        dicts = ["english", "german", "french", "spanish"]

        for d in dicts:
            try:
                with io.open(f"{self.myPath()}/spiderfoot/dicts/ispell/{d}.dict", 'r', encoding='utf8', errors='ignore') as wdct:
                    dlines = wdct.readlines()
            except BaseException as e:
                self.debug(f"Could not read dictionary: {e}")
                continue

            for w in dlines:
                w = w.strip().lower()
                wd[w.split('/')[0]] = True

        return list(wd.keys())

    def dictnames(self) -> list:
        """Return names of available dictionary files.

        Returns:
            list: list of dictionary file names.
        """
        wd = dict()

        dicts = ["names"]

        for d in dicts:
            try:
                wdct = open(f"{self.myPath()}/spiderfoot/dicts/ispell/{d}.dict", 'r')
                dlines = wdct.readlines()
                wdct.close()
            except BaseException as e:
                self.debug("Could not read dictionary: " + str(e))
                continue

            for w in dlines:
                w = w.strip().lower()
                wd[w.split('/')[0]] = True

        return list(wd.keys())

    def resolveHost(self, host: str) -> list:
        """Return a normalised IPv4 resolution of a hostname.

        Args:
            host (str): host to resolve

        Returns:
            list: IP addresses
        """
        if not host:
            self.error(f"Unable to resolve host: {host} (Invalid host)")
            return list()

        addrs = list()
        try:
            addrs = self.normalizeDNS(socket.gethostbyname_ex(host))
        except BaseException as e:
            self.debug(f"Unable to resolve host: {host} ({e})")
            return addrs

        if not addrs:
            self.debug(f"Unable to resolve host: {host}")
            return addrs

        self.debug(f"Resolved {host} to IPv4: {addrs}")

        return list(set(addrs))

    def resolveIP(self, ipaddr: str) -> list:
        """Return a normalised resolution of an IPv4 or IPv6 address.

        Args:
            ipaddr (str): IP address to reverse resolve

        Returns:
            list: list of domain names
        """

        if not self.validIP(ipaddr) and not self.validIP6(ipaddr):
            self.error(f"Unable to reverse resolve {ipaddr} (Invalid IP address)")
            return list()

        self.debug(f"Performing reverse resolve of {ipaddr}")

        try:
            addrs = self.normalizeDNS(socket.gethostbyaddr(ipaddr))
        except BaseException as e:
            self.debug(f"Unable to reverse resolve IP address: {ipaddr} ({e})")
            return list()

        if not addrs:
            self.debug(f"Unable to reverse resolve IP address: {ipaddr}")
            return list()

        self.debug(f"Reverse resolved {ipaddr} to: {addrs}")

        return list(set(addrs))

    def resolveHost6(self, hostname: str) -> list:
        """Return a normalised IPv6 resolution of a hostname.

        Args:
            hostname (str): hostname to resolve

        Returns:
            list
        """
        if not hostname:
            self.error(f"Unable to resolve host: {hostname} (Invalid host)")
            return list()

        addrs = list()
        try:
            res = socket.getaddrinfo(hostname, None, socket.AF_INET6)
            for addr in res:
                if addr[4][0] not in addrs:
                    addrs.append(addr[4][0])
        except BaseException as e:
            self.debug(f"Unable to resolve host: {hostname} ({e})")
            return addrs

        if not addrs:
            self.debug(f"Unable to resolve host: {hostname}")
            return addrs

        self.debug(f"Resolved {hostname} to IPv6: {addrs}")

        return list(set(addrs))

    def validateIP(self, host: str, ip: str) -> bool:
        """Verify a host resolves to a given IP.

        Args:
            host (str): host
            ip (str): IP address

        Returns:
            bool: host resolves to the given IP address
        """
        if not host:
            self.error(f"Unable to resolve host: {host} (Invalid host)")
            return False

        if self.validIP(ip):
            addrs = self.resolveHost(host)
        elif self.validIP6(ip):
            addrs = self.resolveHost6(host)
        else:
            self.error(f"Unable to verify hostname {host} resolves to {ip} (Invalid IP address)")
            return False

        if not addrs:
            return False

        for addr in addrs:
            if str(addr) == ip:
                return True

        return False

    def safeSocket(self, host: str, port: int, timeout: int) -> 'ssl.SSLSocket':
        """Create a safe socket that's using SOCKS/TOR if it was enabled.

        Args:
            host (str): host
            port (int): port
            timeout (int): timeout

        Returns:
            sock
        """
        sock = socket.create_connection((host, int(port)), int(timeout))
        sock.settimeout(int(timeout))
        return sock

    def safeSSLSocket(self, host: str, port: int, timeout: int) -> 'ssl.SSLSocket':
        """Create a safe SSL connection that's using SOCKs/TOR if it was enabled.

        Args:
            host (str): host
            port (int): port
            timeout (int): timeout

        Returns:
            sock
        """
        s = socket.socket()
        s.settimeout(int(timeout))
        s.connect((host, int(port)))
        sock = ssl.wrap_socket(s)
        sock.do_handshake()
        return sock

    def parseRobotsTxt(self, robotsTxtData: str) -> list:
        """Parse the contents of robots.txt.

        Args:
            robotsTxtData (str): robots.txt file contents

        Returns:
            list: list of patterns which should not be followed

        Todo:
            We don't check the User-Agent rule yet.. probably should at some stage

            fix whitespace parsing; ie, " " is not a valid disallowed path
        """
        returnArr = list()

        if not isinstance(robotsTxtData, str):
            return returnArr

        for line in robotsTxtData.splitlines():
            if line.lower().startswith('disallow:'):
                m = re.match(r'disallow:\s*(.[^ #]*)', line, re.IGNORECASE)
                if m:
                    self.debug('robots.txt parsing found disallow: ' + m.group(1))
                    returnArr.append(m.group(1))

        return returnArr

    def parseHashes(self, data: str) -> list:
        """Extract all hashes within the supplied content.

        Args:
            data (str): text to search for hashes

        Returns:
            list: list of hashes
        """
        ret = list()

        if not isinstance(data, str):
            return ret

        hashes = {
            "MD5": re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{32})(?:[^a-fA-F\d]|\b)"),
            "SHA1": re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{40})(?:[^a-fA-F\d]|\b)"),
            "SHA256": re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{64})(?:[^a-fA-F\d]|\b)"),
            "SHA512": re.compile(r"(?:[^a-fA-F\d]|\b)([a-fA-F\d]{128})(?:[^a-fA-F\d]|\b)")
        }

        for h in hashes:
            matches = re.findall(hashes[h], data)
            for match in matches:
                self.debug("Found hash: " + match)
                ret.append((h, match))

        return ret

    def parseEmails(self, data: str) -> list:
        """Extract all email addresses within the supplied content.

        Args:
            data (str): text to search for email addresses

        Returns:
            list: list of email addresses
        """
        if not isinstance(data, str):
            return list()

        emails = set()
        matches = re.findall(r'([\%a-zA-Z\.0-9_\-\+]+@[a-zA-Z\.0-9\-]+\.[a-zA-Z\.0-9\-]+)', data)

        for match in matches:
            if self.validEmail(match):
                emails.add(match)

        return list(emails)

    def parseCreditCards(self, data: str) -> list:
        """Find all credit card numbers with the supplied content.

        Extracts numbers with lengths ranging from 13 - 19 digits

        Checks the numbers using Luhn's algorithm to verify
        if the number is a valid credit card number or not

        Args:
            data (str): text to search for credit card numbers

        Returns:
            list: list of credit card numbers
        """
        if not isinstance(data, str):
            return list()

        creditCards = set()

        # Remove whitespace from data.
        # Credit cards might contain spaces between them
        # which will cause regex mismatch
        data = data.replace(" ", "")

        # Extract all numbers with lengths ranging from 13 - 19 digits
        matches = re.findall(r"[0-9]{13,19}", data)

        # Verify each extracted number using Luhn's algorithm
        for match in matches:
            if int(match) == 0:
                continue

            ccNumber = match

            ccNumberTotal = 0
            isSecondDigit = False

            for digit in ccNumber[::-1]:
                d = int(digit)
                if isSecondDigit:
                    d *= 2
                ccNumberTotal += int(d / 10)
                ccNumberTotal += d % 10

                isSecondDigit = not isSecondDigit
            if ccNumberTotal % 10 == 0:
                self.debug("Found credit card number: " + match)
                creditCards.add(match)
        return list(creditCards)

    def getCountryCodeDict(self) -> dict:
        """Dictionary of country codes and associated country names.

        Returns:
            dict: country codes and associated country names
        """

        return {
            "AF": "Afghanistan",
            "AX": "Aland Islands",
            "AL": "Albania",
            "DZ": "Algeria",
            "AS": "American Samoa",
            "AD": "Andorra",
            "AO": "Angola",
            "AI": "Anguilla",
            "AQ": "Antarctica",
            "AG": "Antigua and Barbuda",
            "AR": "Argentina",
            "AM": "Armenia",
            "AW": "Aruba",
            "AU": "Australia",
            "AT": "Austria",
            "AZ": "Azerbaijan",
            "BS": "Bahamas",
            "BH": "Bahrain",
            "BD": "Bangladesh",
            "BB": "Barbados",
            "BY": "Belarus",
            "BE": "Belgium",
            "BZ": "Belize",
            "BJ": "Benin",
            "BM": "Bermuda",
            "BT": "Bhutan",
            "BO": "Bolivia",
            "BQ": "Bonaire, Saint Eustatius and Saba",
            "BA": "Bosnia and Herzegovina",
            "BW": "Botswana",
            "BV": "Bouvet Island",
            "BR": "Brazil",
            "IO": "British Indian Ocean Territory",
            "VG": "British Virgin Islands",
            "BN": "Brunei",
            "BG": "Bulgaria",
            "BF": "Burkina Faso",
            "BI": "Burundi",
            "KH": "Cambodia",
            "CM": "Cameroon",
            "CA": "Canada",
            "CV": "Cape Verde",
            "KY": "Cayman Islands",
            "CF": "Central African Republic",
            "TD": "Chad",
            "CL": "Chile",
            "CN": "China",
            "CX": "Christmas Island",
            "CC": "Cocos Islands",
            "CO": "Colombia",
            "KM": "Comoros",
            "CK": "Cook Islands",
            "CR": "Costa Rica",
            "HR": "Croatia",
            "CU": "Cuba",
            "CW": "Curacao",
            "CY": "Cyprus",
            "CZ": "Czech Republic",
            "CD": "Democratic Republic of the Congo",
            "DK": "Denmark",
            "DJ": "Djibouti",
            "DM": "Dominica",
            "DO": "Dominican Republic",
            "TL": "East Timor",
            "EC": "Ecuador",
            "EG": "Egypt",
            "SV": "El Salvador",
            "GQ": "Equatorial Guinea",
            "ER": "Eritrea",
            "EE": "Estonia",
            "ET": "Ethiopia",
            "FK": "Falkland Islands",
            "FO": "Faroe Islands",
            "FJ": "Fiji",
            "FI": "Finland",
            "FR": "France",
            "GF": "French Guiana",
            "PF": "French Polynesia",
            "TF": "French Southern Territories",
            "GA": "Gabon",
            "GM": "Gambia",
            "GE": "Georgia",
            "DE": "Germany",
            "GH": "Ghana",
            "GI": "Gibraltar",
            "GR": "Greece",
            "GL": "Greenland",
            "GD": "Grenada",
            "GP": "Guadeloupe",
            "GU": "Guam",
            "GT": "Guatemala",
            "GG": "Guernsey",
            "GN": "Guinea",
            "GW": "Guinea-Bissau",
            "GY": "Guyana",
            "HT": "Haiti",
            "HM": "Heard Island and McDonald Islands",
            "HN": "Honduras",
            "HK": "Hong Kong",
            "HU": "Hungary",
            "IS": "Iceland",
            "IN": "India",
            "ID": "Indonesia",
            "IR": "Iran",
            "IQ": "Iraq",
            "IE": "Ireland",
            "IM": "Isle of Man",
            "IL": "Israel",
            "IT": "Italy",
            "CI": "Ivory Coast",
            "JM": "Jamaica",
            "JP": "Japan",
            "JE": "Jersey",
            "JO": "Jordan",
            "KZ": "Kazakhstan",
            "KE": "Kenya",
            "KI": "Kiribati",
            "XK": "Kosovo",
            "KW": "Kuwait",
            "KG": "Kyrgyzstan",
            "LA": "Laos",
            "LV": "Latvia",
            "LB": "Lebanon",
            "LS": "Lesotho",
            "LR": "Liberia",
            "LY": "Libya",
            "LI": "Liechtenstein",
            "LT": "Lithuania",
            "LU": "Luxembourg",
            "MO": "Macao",
            "MK": "Macedonia",
            "MG": "Madagascar",
            "MW": "Malawi",
            "MY": "Malaysia",
            "MV": "Maldives",
            "ML": "Mali",
            "MT": "Malta",
            "MH": "Marshall Islands",
            "MQ": "Martinique",
            "MR": "Mauritania",
            "MU": "Mauritius",
            "YT": "Mayotte",
            "MX": "Mexico",
            "FM": "Micronesia",
            "MD": "Moldova",
            "MC": "Monaco",
            "MN": "Mongolia",
            "ME": "Montenegro",
            "MS": "Montserrat",
            "MA": "Morocco",
            "MZ": "Mozambique",
            "MM": "Myanmar",
            "NA": "Namibia",
            "NR": "Nauru",
            "NP": "Nepal",
            "NL": "Netherlands",
            "AN": "Netherlands Antilles",
            "NC": "New Caledonia",
            "NZ": "New Zealand",
            "NI": "Nicaragua",
            "NE": "Niger",
            "NG": "Nigeria",
            "NU": "Niue",
            "NF": "Norfolk Island",
            "KP": "North Korea",
            "MP": "Northern Mariana Islands",
            "NO": "Norway",
            "OM": "Oman",
            "PK": "Pakistan",
            "PW": "Palau",
            "PS": "Palestinian Territory",
            "PA": "Panama",
            "PG": "Papua New Guinea",
            "PY": "Paraguay",
            "PE": "Peru",
            "PH": "Philippines",
            "PN": "Pitcairn",
            "PL": "Poland",
            "PT": "Portugal",
            "PR": "Puerto Rico",
            "QA": "Qatar",
            "CG": "Republic of the Congo",
            "RE": "Reunion",
            "RO": "Romania",
            "RU": "Russia",
            "RW": "Rwanda",
            "BL": "Saint Barthelemy",
            "SH": "Saint Helena",
            "KN": "Saint Kitts and Nevis",
            "LC": "Saint Lucia",
            "MF": "Saint Martin",
            "PM": "Saint Pierre and Miquelon",
            "VC": "Saint Vincent and the Grenadines",
            "WS": "Samoa",
            "SM": "San Marino",
            "ST": "Sao Tome and Principe",
            "SA": "Saudi Arabia",
            "SN": "Senegal",
            "RS": "Serbia",
            "CS": "Serbia and Montenegro",
            "SC": "Seychelles",
            "SL": "Sierra Leone",
            "SG": "Singapore",
            "SX": "Sint Maarten",
            "SK": "Slovakia",
            "SI": "Slovenia",
            "SB": "Solomon Islands",
            "SO": "Somalia",
            "ZA": "South Africa",
            "GS": "South Georgia and the South Sandwich Islands",
            "KR": "South Korea",
            "SS": "South Sudan",
            "ES": "Spain",
            "LK": "Sri Lanka",
            "SD": "Sudan",
            "SR": "Suriname",
            "SJ": "Svalbard and Jan Mayen",
            "SZ": "Swaziland",
            "SE": "Sweden",
            "CH": "Switzerland",
            "SY": "Syria",
            "TW": "Taiwan",
            "TJ": "Tajikistan",
            "TZ": "Tanzania",
            "TH": "Thailand",
            "TG": "Togo",
            "TK": "Tokelau",
            "TO": "Tonga",
            "TT": "Trinidad and Tobago",
            "TN": "Tunisia",
            "TR": "Turkey",
            "TM": "Turkmenistan",
            "TC": "Turks and Caicos Islands",
            "TV": "Tuvalu",
            "VI": "U.S. Virgin Islands",
            "UG": "Uganda",
            "UA": "Ukraine",
            "AE": "United Arab Emirates",
            "GB": "United Kingdom",
            "US": "United States",
            "UM": "United States Minor Outlying Islands",
            "UY": "Uruguay",
            "UZ": "Uzbekistan",
            "VU": "Vanuatu",
            "VA": "Vatican",
            "VE": "Venezuela",
            "VN": "Vietnam",
            "WF": "Wallis and Futuna",
            "EH": "Western Sahara",
            "YE": "Yemen",
            "ZM": "Zambia",
            "ZW": "Zimbabwe",
            # Below are not country codes but recognized as regions / TLDs
            "AC": "Ascension Island",
            "EU": "European Union",
            "SU": "Soviet Union",
            "UK": "United Kingdom"
        }

    def countryNameFromCountryCode(self, countryCode: str) -> str:
        """Convert a country code to full country name

        Args:
            countryCode (str): country code

        Returns:
            str: country name
        """
        if not isinstance(countryCode, str):
            return None

        return self.getCountryCodeDict().get(countryCode.upper())

    def countryNameFromTld(self, tld: str) -> str:
        """Retrieve the country name associated with a TLD.

        Args:
            tld (str): Top level domain

        Returns:
            str: country name
        """
        if not isinstance(tld, str):
            return None

        country_name = self.getCountryCodeDict().get(tld.upper())

        if country_name:
            return country_name

        country_tlds = {
            # List of TLD not associated with any country
            "COM": "United States",
            "NET": "United States",
            "ORG": "United States",
            "GOV": "United States",
            "MIL": "United States"
        }

        country_name = country_tlds.get(tld.upper())

        if country_name:
            return country_name

        return None

    def parseIBANNumbers(self, data: str) -> list:
        """Find all International Bank Account Numbers (IBANs) within the supplied content.

        Extracts possible IBANs using a generic regex.

        Checks whether possible IBANs are valid or not
        using country-wise length check and Mod 97 algorithm.

        Args:
            data (str): text to search for IBANs

        Returns:
            list: list of IBAN
        """
        if not isinstance(data, str):
            return list()

        ibans = set()

        # Dictionary of country codes and their respective IBAN lengths
        ibanCountryLengths = {
            "AL": 28, "AD": 24, "AT": 20, "AZ": 28,
            "ME": 22, "BH": 22, "BY": 28, "BE": 16,
            "BA": 20, "BR": 29, "BG": 22, "CR": 22,
            "HR": 21, "CY": 28, "CZ": 24, "DK": 18,
            "DO": 28, "EG": 29, "SV": 28, "FO": 18,
            "FI": 18, "FR": 27, "GE": 22, "DE": 22,
            "GI": 23, "GR": 27, "GL": 18, "GT": 28,
            "VA": 22, "HU": 28, "IS": 26, "IQ": 23,
            "IE": 22, "IL": 23, "JO": 30, "KZ": 20,
            "XK": 20, "KW": 30, "LV": 21, "LB": 28,
            "LI": 21, "LT": 20, "LU": 20, "MT": 31,
            "MR": 27, "MU": 30, "MD": 24, "MC": 27,
            "DZ": 24, "AO": 25, "BJ": 28, "VG": 24,
            "BF": 27, "BI": 16, "CM": 27, "CV": 25,
            "CG": 27, "EE": 20, "GA": 27, "GG": 22,
            "IR": 26, "IM": 22, "IT": 27, "CI": 28,
            "JE": 22, "MK": 19, "MG": 27, "ML": 28,
            "MZ": 25, "NL": 18, "NO": 15, "PK": 24,
            "PS": 29, "PL": 28, "PT": 25, "QA": 29,
            "RO": 24, "LC": 32, "SM": 27, "ST": 25,
            "SA": 24, "SN": 28, "RS": 22, "SC": 31,
            "SK": 24, "SI": 19, "ES": 24, "CH": 21,
            "TL": 23, "TN": 24, "TR": 26, "UA": 29,
            "AE": 23, "GB": 22, "SE": 24
        }

        # Normalize input data to remove whitespace
        data = data.replace(" ", "")

        # Extract alphanumeric characters of lengths ranging from 15 to 32
        # and starting with two characters
        matches = re.findall("[A-Za-z]{2}[A-Za-z0-9]{13,30}", data)

        for match in matches:
            iban = match.upper()

            countryCode = iban[0:2]

            if countryCode not in ibanCountryLengths.keys():
                continue

            if len(iban) != ibanCountryLengths[countryCode]:
                continue

            # Convert IBAN to integer format.
            # Move the first 4 characters to the end of the string,
            # then convert all characters to integers; where A = 10, B = 11, ...., Z = 35
            iban_int = iban[4:] + iban[0:4]
            for character in iban_int:
                if character.isalpha():
                    iban_int = iban_int.replace(character, str((ord(character) - 65) + 10))

            # Check IBAN integer mod 97 for remainder
            if int(iban_int) % 97 != 1:
                continue

            self.debug("Found IBAN: %s" % iban)
            ibans.add(iban)

        return list(ibans)

    def sslDerToPem(self, der_cert: bytes) -> str:
        """Given a certificate as a DER-encoded blob of bytes, returns a PEM-encoded string version of the same certificate.

        Args:
            der_cert (bytes): certificate in DER format

        Returns:
            str: PEM-encoded certificate as a byte string

        Raises:
            TypeError: arg type was invalid
        """

        if not isinstance(der_cert, bytes):
            raise TypeError("der_cert is %s; expected bytes()" % type(der_cert))

        return ssl.DER_cert_to_PEM_cert(der_cert)

    def parseCert(self, rawcert: str, fqdn: str = None, expiringdays: int = 30) -> dict:
        """Parse a PEM-format SSL certificate.

        Args:
            rawcert (str): PEM-format SSL certificate
            fqdn (str): TBD
            expiringdays (int): The certificate will be considered as "expiring" if within this number of days of expiry.

        Returns:
            dict: certificate details
        """
        if not rawcert:
            self.error(f"Invalid certificate: {rawcert}")
            return None

        ret = dict()
        if '\r' in rawcert:
            rawcert = rawcert.replace('\r', '')
        if isinstance(rawcert, str):
            rawcert = rawcert.encode('utf-8')

        from cryptography.hazmat.backends.openssl import backend
        cert = cryptography.x509.load_pem_x509_certificate(rawcert, backend)
        sslcert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, rawcert)
        sslcert_dump = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, sslcert)

        ret['text'] = sslcert_dump.decode('utf-8', errors='replace')
        ret['issuer'] = str(cert.issuer)
        ret['altnames'] = list()
        ret['expired'] = False
        ret['expiring'] = False
        ret['mismatch'] = False
        ret['certerror'] = False
        ret['issued'] = str(cert.subject)

        # Expiry info
        try:
            notafter = datetime.strptime(sslcert.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ")
            ret['expiry'] = int(notafter.strftime("%s"))
            ret['expirystr'] = notafter.strftime("%Y-%m-%d %H:%M:%S")
            now = int(time.time())
            warnexp = now + (expiringdays * 86400)
            if ret['expiry'] <= warnexp:
                ret['expiring'] = True
            if ret['expiry'] <= now:
                ret['expired'] = True
        except BaseException as e:
            self.error(f"Error processing date in certificate: {e}")
            ret['certerror'] = True
            return ret

        # SANs
        try:
            ext = cert.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName)
            for x in ext.value:
                if isinstance(x, cryptography.x509.DNSName):
                    ret['altnames'].append(x.value.lower().encode('raw_unicode_escape').decode("ascii", errors='replace'))
        except BaseException as e:
            self.debug("Problem processing certificate: " + str(e))
            pass

        certhosts = list()
        try:
            attrs = cert.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)

            if len(attrs) == 1:
                name = attrs[0].value.lower()
                # CN often duplicates one of the SANs, don't add it then
                if name not in ret['altnames']:
                    certhosts.append(name)
        except BaseException as e:
            self.debug("Problem processing certificate: " + str(e))
            pass

        # Check for mismatch
        if fqdn and ret['issued']:
            fqdn = fqdn.lower()

            try:
                # Extract the CN from the issued section
                if "cn=" + fqdn in ret['issued'].lower():
                    certhosts.append(fqdn)

                # Extract subject alternative names
                for host in ret['altnames']:
                    certhosts.append(host.replace("dns:", ""))

                ret['hosts'] = certhosts

                self.debug("Checking for " + fqdn + " in certificate subject")
                fqdn_tld = ".".join(fqdn.split(".")[1:]).lower()

                found = False
                for chost in certhosts:
                    if chost == fqdn:
                        found = True
                    if chost == "*." + fqdn_tld:
                        found = True
                    if chost == fqdn_tld:
                        found = True

                if not found:
                    ret['mismatch'] = True
            except BaseException as e:
                self.error("Error processing certificate: " + str(e))
                ret['certerror'] = True

        return ret

    def extractUrls(self, content: str) -> list:
        """Extract all URLs from a string.

        Args:
            content (str): text to search for URLs

        Returns:
            list: list of identified URLs
        """

        # https://tools.ietf.org/html/rfc3986#section-3.3
        return re.findall(r"(https?://[a-zA-Z0-9-\.:]+/[\-\._~!\$&'\(\)\*\+\,\;=:@/a-zA-Z0-9]*)", html.unescape(content))

    def parseLinks(self, url: str, data: str, domains: list) -> list:
        """Find all URLs within the supplied content.

        This does not fetch any URLs!
        A dictionary will be returned, where each link will have the keys
        'source': The URL where the link was obtained from
        'original': What the link looked like in the content it was obtained from
        The key will be the *absolute* URL of the link obtained, so for example if
        the link '/abc' was obtained from 'http://xyz.com', the key in the dict will
        be 'http://xyz.com/abc' with the 'original' attribute set to '/abc'

        Args:
            url (str): base URL used to construct absolute URLs from relative URLs
            data (str): data to examine for links
            domains: TBD

        Returns:
            list: links
        """
        returnLinks = dict()

        if not isinstance(data, str):
            self.debug("parseLinks() data is %s; expected str()" % type(data))
            return returnLinks

        if not data:
            self.debug("parseLinks() called with no data to parse.")
            return returnLinks

        if isinstance(domains, str):
            domains = [domains]

        tags = {
            'a': 'href',
            'img': 'src',
            'script': 'src',
            'link': 'href',
            'area': 'href',
            'base': 'href',
            'form': 'action'
        }

        try:
            proto = url.split(":")[0]
        except BaseException:
            proto = "http"
        if proto is None:
            proto = "http"

        urlsRel = []

        try:
            for t in list(tags.keys()):
                for lnk in BeautifulSoup(data, "lxml", parse_only=SoupStrainer(t)).find_all(t):
                    if lnk.has_attr(tags[t]):
                        urlsRel.append(lnk[tags[t]])
        except BaseException as e:
            self.error("Error parsing with BeautifulSoup: " + str(e))
            return returnLinks

        # Loop through all the URLs/links found
        for link in urlsRel:
            if not isinstance(link, str):
                link = str(link)
            link = link.strip()
            linkl = link.lower()
            absLink = None

            if len(link) < 1:
                continue

            # Don't include stuff likely part of some dynamically built incomplete
            # URL found in Javascript code (character is part of some logic)
            if link[len(link) - 1] == '.' or link[0] == '+' or 'javascript:' in linkl or '()' in link:
                self.debug('unlikely link: ' + link)
                continue

            # Filter in-page links
            if re.match('.*#.[^/]+', link):
                self.debug('in-page link: ' + link)
                continue

            # Ignore mail links
            if 'mailto:' in linkl:
                self.debug("Ignoring mail link: " + link)
                continue

            # URL decode links
            if '%2f' in linkl:
                link = urllib.parse.unquote(link)

            # Capture the absolute link:
            # If the link contains ://, it is already an absolute link
            if '://' in link:
                absLink = link

            # If the link starts with a /, the absolute link is off the base URL
            if link.startswith('/'):
                absLink = self.urlBaseUrl(url) + link

            # Protocol relative URLs
            if link.startswith('//'):
                absLink = proto + ':' + link

            # Maybe the domain was just mentioned and not a link, so we make it one
            for domain in domains:
                if absLink is None and domain.lower() in link.lower():
                    absLink = proto + '://' + link

            # Otherwise, it's a flat link within the current directory
            if absLink is None:
                absLink = self.urlBaseDir(url) + link

            # Translate any relative pathing (../)
            absLink = self.urlRelativeToAbsolute(absLink)
            returnLinks[absLink] = {'source': url, 'original': link}

        return returnLinks

    def urlEncodeUnicode(self, url: str) -> str:
        """Encode a string as unicode.

        Args:
            url (str): URL to encode

        Returns:
            str: unicode string
        """
        return re.sub('[\x80-\xFF]', lambda c: '%%%02x' % ord(c.group(0)), url)

    def getSession(self) -> 'requests.sessions.Session':
        """Return requests session object.

        Returns:
            requests.sessions.Session: requests session
        """
        session = requests.session()
        if self.socksProxy:
            session.proxies = {
                'http': self.socksProxy,
                'https': self.socksProxy,
            }
        return session

    def removeUrlCreds(self, url: str) -> str:
        """Remove potentially sensitive strings (such as "key=..." and "password=...") from a string.

        Used to remove potential credentials from URLs prior during logging.

        Args:
            url (str): URL

        Returns:
            str: Sanitized URL
        """
        pats = {
            r'key=\S+': "key=XXX",
            r'pass=\S+': "pass=XXX",
            r'user=\S+': "user=XXX",
            r'password=\S+': "password=XXX"
        }

        ret = url
        for pat in pats:
            ret = re.sub(pat, pats[pat], ret, re.IGNORECASE)

        return ret

    def isValidLocalOrLoopbackIp(self, ip: str) -> bool:
        """Check if the specified IPv4 or IPv6 address is a loopback or local network IP address (IPv4 RFC1918 / IPv6 RFC4192 ULA).

        Args:
            ip (str): IPv4 or IPv6 address

        Returns:
            bool: IP address is local or loopback
        """
        if not self.validIP(ip) and not self.validIP6(ip):
            return False

        if netaddr.IPAddress(ip).is_private():
            return True

        if netaddr.IPAddress(ip).is_loopback():
            return True

        return False

    def useProxyForUrl(self, url: str) -> bool:
        """Check if the configured proxy should be used to connect to a specified URL.

        Args:
            url (str): The URL to check

        Returns:
            bool: should the configured proxy be used?

        Todo:
            Allow using TOR only for .onion addresses
        """
        host = self.urlFQDN(url).lower()

        if not self.opts['_socks1type']:
            return False

        proxy_host = self.opts['_socks2addr']

        if not proxy_host:
            return False

        proxy_port = self.opts['_socks3port']

        if not proxy_port:
            return False

        # Never proxy requests to the proxy host
        if host == proxy_host.lower():
            return False

        # Never proxy RFC1918 addresses on the LAN or the local network interface
        if self.validIP(host):
            if netaddr.IPAddress(host).is_private():
                return False
            if netaddr.IPAddress(host).is_loopback():
                return False

        # Never proxy local hostnames
        else:
            neverProxyNames = ['local', 'localhost']
            if host in neverProxyNames:
                return False

            for s in neverProxyNames:
                if host.endswith(s):
                    return False

        return True

    def fetchUrl(
        self,
        url: str,
        fatal: bool = False,
        cookies: str = None,
        timeout: int = 30,
        useragent: str = "SpiderFoot",
        headers: dict = None,
        noLog: bool = False,
        postData: str = None,
        disableContentEncoding: bool = False,
        sizeLimit: int = None,
        headOnly: bool = False,
        verify: bool = True
    ) -> dict:
        """Fetch a URL and return the HTTP response as a dictionary.

        Args:
            url (str): URL to fetch
            fatal (bool): raise an exception upon request error
            cookies (str): cookies
            timeout (int): timeout
            useragent (str): user agent header
            headers (dict): headers
            noLog (bool): do not log request
            postData (str): HTTP POST data
            disableContentEncoding (bool): do not UTF-8 encode response body
            sizeLimit (int): size threshold
            headOnly (bool): use HTTP HEAD method
            verify (bool): use HTTPS SSL/TLS verification

        Returns:
            dict: HTTP response
        """
        if not url:
            return None

        result = {
            'code': None,
            'status': None,
            'content': None,
            'headers': None,
            'realurl': url
        }

        url = url.strip()

        try:
            parsed_url = urllib.parse.urlparse(url)
        except Exception:
            self.debug(f"Could not parse URL: {url}")
            return None

        if parsed_url.scheme != 'http' and parsed_url.scheme != 'https':
            self.debug(f"Invalid URL scheme for URL: {url}")
            return None

        request_log = []

        proxies = dict()
        if self.useProxyForUrl(url):
            proxies = {
                'http': self.socksProxy,
                'https': self.socksProxy,
            }

        header = dict()
        btime = time.time()

        if isinstance(useragent, list):
            header['User-Agent'] = random.SystemRandom().choice(useragent)
        else:
            header['User-Agent'] = useragent

        # Add custom headers
        if isinstance(headers, dict):
            for k in list(headers.keys()):
                header[k] = str(headers[k])

        request_log.append(f"proxy={self.socksProxy}")
        request_log.append(f"user-agent={header['User-Agent']}")
        request_log.append(f"timeout={timeout}")
        request_log.append(f"cookies={cookies}")

        if sizeLimit or headOnly:
            if not noLog:
                self.info(f"Fetching (HEAD): {self.removeUrlCreds(url)} ({', '.join(request_log)})")

            try:
                hdr = self.getSession().head(
                    url,
                    headers=header,
                    proxies=proxies,
                    verify=verify,
                    timeout=timeout
                )
            except Exception as e:
                if not noLog:
                    self.error(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {url}")
                    self.error(traceback.format_exc())

                if fatal:
                    self.fatal(f"URL could not be fetched ({e})")

                return result

            size = int(hdr.headers.get('content-length', 0))
            newloc = hdr.headers.get('location', url).strip()

            # Relative re-direct
            if newloc.startswith("/") or newloc.startswith("../"):
                newloc = self.urlBaseUrl(url) + newloc
            result['realurl'] = newloc
            result['code'] = str(hdr.status_code)

            if headOnly:
                return result

            if size > sizeLimit:
                return result

            if result['realurl'] != url:
                if not noLog:
                    self.info(f"Fetching (HEAD): {self.removeUrlCreds(result['realurl'])} ({', '.join(request_log)})")

                try:
                    hdr = self.getSession().head(
                        result['realurl'],
                        headers=header,
                        proxies=proxies,
                        verify=verify,
                        timeout=timeout
                    )
                    size = int(hdr.headers.get('content-length', 0))
                    result['realurl'] = hdr.headers.get('location', result['realurl'])
                    result['code'] = str(hdr.status_code)

                    if size > sizeLimit:
                        return result

                except Exception as e:
                    if not noLog:
                        self.error(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {result['realurl']}")
                        self.error(traceback.format_exc())

                    if fatal:
                        self.fatal(f"URL could not be fetched ({e})")

                    return result

        try:
            if postData:
                if not noLog:
                    self.info(f"Fetching (POST): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
                res = self.getSession().post(
                    url,
                    data=postData,
                    headers=header,
                    proxies=proxies,
                    allow_redirects=True,
                    cookies=cookies,
                    timeout=timeout,
                    verify=verify
                )
            else:
                if not noLog:
                    self.info(f"Fetching (GET): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
                res = self.getSession().get(
                    url,
                    headers=header,
                    proxies=proxies,
                    allow_redirects=True,
                    cookies=cookies,
                    timeout=timeout,
                    verify=verify
                )
        except requests.exceptions.RequestException:
            self.error(f"Failed to connect to {url}")
            return result
        except Exception as e:
            if not noLog:
                self.error(f"Unexpected exception ({e}) occurred fetching URL: {url}")
                self.error(traceback.format_exc())

            if fatal:
                self.fatal(f"URL could not be fetched ({e})")

            return result

        try:
            result['headers'] = dict()

            for header, value in res.headers.items():
                result['headers'][str(header).lower()] = str(value)

            # Sometimes content exceeds the size limit after decompression
            if sizeLimit and len(res.content) > sizeLimit:
                self.debug(f"Content exceeded size limit ({sizeLimit}), so returning no data just headers")
                result['realurl'] = res.url
                result['code'] = str(res.status_code)
                return result

            refresh_header = result['headers'].get('refresh')
            if refresh_header:
                try:
                    newurl = refresh_header.split(";url=")[1]
                except Exception as e:
                    self.debug(f"Refresh header '{refresh_header}' found, but not parsable: {e}")
                    return result

                self.debug(f"Refresh header '{refresh_header}' found, re-directing to {self.removeUrlCreds(newurl)}")

                return self.fetchUrl(
                    newurl,
                    fatal,
                    cookies,
                    timeout,
                    useragent,
                    headers,
                    noLog,
                    postData,
                    disableContentEncoding,
                    sizeLimit,
                    headOnly
                )

            result['realurl'] = res.url
            result['code'] = str(res.status_code)
            if disableContentEncoding:
                result['content'] = res.content
            else:
                for encoding in ("utf-8", "ascii"):
                    try:
                        result["content"] = res.content.decode(encoding)
                    except UnicodeDecodeError:
                        pass
                    else:
                        break
                else:
                    result["content"] = res.content

            if fatal:
                try:
                    res.raise_for_status()
                except requests.exceptions.HTTPError:
                    self.fatal(f"URL could not be fetched ({res.status_code}) / {res.content})")

        except Exception as e:
            self.error(f"Unexpected exception ({e}) occurred parsing response for URL: {url}")
            self.error(traceback.format_exc())

            if fatal:
                self.fatal(f"URL could not be fetched ({e})")

            result['content'] = None
            result['status'] = str(e)

        atime = time.time()
        t = str(atime - btime)
        self.info(f"Fetched {self.removeUrlCreds(url)} ({len(result['content'] or '')} bytes in {t}s)")
        return result

    def checkDnsWildcard(self, target: str) -> bool:
        """Check if wildcard DNS is enabled by looking up a random subdomain.

        Args:
            target (str): TBD

        Returns:
            bool: Domain returns DNS records for any subdomains
        """
        if not target:
            return False

        randpool = 'bcdfghjklmnpqrstvwxyz3456789'
        randhost = ''.join([random.SystemRandom().choice(randpool) for x in range(10)])

        if not self.resolveHost(randhost + "." + target):
            return False

        return True

    def cveInfo(self, cveId: str, sources="circl,nist") -> (str, str):
        """Look up a CVE ID for more information in the first available source.

        Args:
            cveId (str): CVE ID, e.g. CVE-2018-15473
            sources (str): Comma-separated list of sources to query. Options available are circl and nist

        Returns:
            (str, str): Appropriate event type and descriptive text
        """
        sources = sources.split(",")
        # VULNERABILITY_GENERAL is the generic type in case we don't have
        # a real/mappable CVE.
        eventType = "VULNERABILITY_GENERAL"

        def cveRating(score):
            if score == "Unknown":
                return None
            if score >= 0 and score <= 3.9:
                return "LOW"
            if score >= 4.0 and score <= 6.9:
                return "MEDIUM"
            if score >= 7.0 and score <= 8.9:
                return "HIGH"
            if score >= 9.0:
                return "CRITICAL"
            return None

        for source in sources:
            jsondata = self.cacheGet(f"{source}-{cveId}", 86400)

            if not jsondata:
                # Fetch data from source
                if source == "nist":
                    ret = self.fetchUrl(f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cveId}", timeout=5)
                if source == "circl":
                    ret = self.fetchUrl(f"https://cve.circl.lu/api/cve/{cveId}", timeout=5)

                if not ret:
                    continue

                if not ret['content']:
                    continue

                self.cachePut(f"{source}-{cveId}", ret['content'])
                jsondata = ret['content']

            try:
                data = json.loads(jsondata)

                if source == "circl":
                    score = data.get('cvss', 'Unknown')
                    rating = cveRating(score)
                    if rating:
                        eventType = f"VULNERABILITY_CVE_{rating}"
                        return (eventType, f"{cveId}\n<SFURL>https://nvd.nist.gov/vuln/detail/{cveId}</SFURL>\n"
                                f"Score: {score}\nDescription: {data.get('summary', 'Unknown')}")

                if source == "nist":
                    try:
                        if data['CVE_Items'][0]['impact'].get('baseMetricV3'):
                            score = data['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
                        else:
                            score = data['CVE_Items'][0]['impact']['baseMetricV2']['cvssV2']['baseScore']
                        rating = cveRating(score)
                        if rating:
                            eventType = f"VULNERABILITY_CVE_{rating}"
                    except Exception:
                        score = "Unknown"

                    try:
                        descr = data['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
                    except Exception:
                        descr = "Unknown"

                    return (eventType, f"{cveId}\n<SFURL>https://nvd.nist.gov/vuln/detail/{cveId}</SFURL>\n"
                            f"Score: {score}\nDescription: {descr}")
            except BaseException as e:
                self.debug(f"Unable to parse CVE response from {source.upper()}: {e}")
                continue

        return (eventType, f"{cveId}\nScore: Unknown\nDescription: Unknown")

    def googleIterate(self, searchString: str, opts: dict = None) -> dict:
        """Request search results from the Google API.

        Will return a dict:
        {
          "urls": a list of urls that match the query string,
          "webSearchUrl": url for Google results page,
        }

        Options accepted:
            useragent: User-Agent string to use
            timeout: API call timeout

        Args:
            searchString (str) :TBD
            opts (dict): TBD

        Returns:
            dict: Search results as {"webSearchUrl": "URL", "urls": [results]}
        """
        if opts is None:
            opts = {}
        search_string = searchString.replace(" ", "%20")
        params = urllib.parse.urlencode({
            "cx": opts["cse_id"],
            "key": opts["api_key"],
        })

        response = self.fetchUrl(
            f"https://www.googleapis.com/customsearch/v1?q={search_string}&{params}",
            timeout=opts["timeout"],
        )

        if response['code'] != '200':
            self.error("Failed to get a valid response from the Google API")
            return None

        try:
            response_json = json.loads(response['content'])
        except ValueError:
            self.error("The key 'content' in the Google API response doesn't contain valid JSON.")
            return None

        if "items" not in response_json:
            return None

        # We attempt to make the URL params look as authentically human as possible
        params = urllib.parse.urlencode({
            "ie": "utf-8",
            "oe": "utf-8",
            "aq": "t",
            "rls": "org.mozilla:en-US:official",
            "client": "firefox-a",
        })

        return {
            "urls": [str(k['link']) for k in response_json['items']],
            "webSearchUrl": f"https://www.google.com/search?q={search_string}&{params}"
        }

    def bingIterate(self, searchString: str, opts: dict = {}) -> dict:
        """Request search results from the Bing API.

        Will return a dict:
        {
          "urls": a list of urls that match the query string,
          "webSearchUrl": url for bing results page,
        }

        Options accepted:
            count: number of search results to request from the API
            useragent: User-Agent string to use
            timeout: API call timeout

        Args:
            searchString (str): TBD
            opts (dict): TBD

        Returns:
            dict: Search results as {"webSearchUrl": "URL", "urls": [results]}
        """

        search_string = searchString.replace(" ", "%20")
        params = urllib.parse.urlencode({
            "responseFilter": "Webpages",
            "count": opts["count"],
        })

        response = self.fetchUrl(
            f"https://api.cognitive.microsoft.com/bing/v7.0/search?q={search_string}&{params}",
            timeout=opts["timeout"],
            useragent=opts["useragent"],
            headers={"Ocp-Apim-Subscription-Key": opts["api_key"]},
        )

        if response['code'] != '200':
            self.error("Failed to get a valid response from the Bing API")
            return None

        try:
            response_json = json.loads(response['content'])
        except ValueError:
            self.error("The key 'content' in the bing API response doesn't contain valid JSON.")
            return None

        if ("webPages" in response_json and "value" in response_json["webPages"] and "webSearchUrl" in response_json["webPages"]):
            return {
                "urls": [result["url"] for result in response_json["webPages"]["value"]],
                "webSearchUrl": response_json["webPages"]["webSearchUrl"],
            }

        return None

# end of SpiderFoot class
