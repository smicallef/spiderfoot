#  -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sflib
# Purpose:      Common functions used by SpiderFoot modules.
#
# Author:      Steve Micallef <steve@binarypool.com>
#
# Created:     26/03/2012
# Copyright:   (c) Steve Micallef 2012
# Licence:     MIT
# -------------------------------------------------------------------------------

import hashlib
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
import urllib.error
import urllib.parse
import urllib.request
from copy import deepcopy
from datetime import datetime

import cryptography
import dns.resolver
import netaddr
import OpenSSL
import requests
import urllib3
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
            raise TypeError(f"options is {type(options)}; expected dict()")

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
            dbh (SpiderFootDb): database handle
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
        """Store data to the cache.

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
        """Retreive data from the cache.

        Args:
            label (str): Name of the cached data to retrieve
            timeoutHrs (int): Age of the cached data (in hours)
                              for which the data is considered to be too old and ignored.

        Returns:
            str: cached data
        """
        if not label:
            return None

        pathLabel = hashlib.sha224(label.encode('utf-8')).hexdigest()
        cacheFile = SpiderFootHelpers.cachePath() + "/" + pathLabel
        try:
            cache_stat = os.stat(cacheFile)
        except OSError:
            return None

        if cache_stat.st_size == 0:
            return None

        if cache_stat.st_mtime > time.time() - timeoutHrs * 3600 or timeoutHrs == 0:
            with open(cacheFile, "r", encoding='utf-8') as fp:
                return fp.read()

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
            raise TypeError(f"opts['__modules__'] is {type(opts['__modules__'])}; expected dict()")

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
            raise TypeError(f"opts is {type(opts)}; expected dict()")
        if not isinstance(referencePoint, dict):
            raise TypeError(f"referencePoint is {type(referencePoint)}; expected dict()")

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

        baseurl = SpiderFootHelpers.urlBaseUrl(url)
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
            self.error(f"Invalid domain list: {domainList}")
            return set()

        keywords = list()
        for domain in domainList:
            keywords.append(self.domainKeyword(domain, tldList))

        self.debug(f"Keywords: {keywords}")
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
            return netaddr.IPNetwork(str(cidr)).size > 0
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
            fqdn (str): expected FQDN for certificate
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
            self.debug(f"Problem processing certificate: {e}")

        certhosts = list()
        try:
            attrs = cert.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)

            if len(attrs) == 1:
                name = attrs[0].value.lower()
                # CN often duplicates one of the SANs, don't add it then
                if name not in ret['altnames']:
                    certhosts.append(name)
        except BaseException as e:
            self.debug(f"Problem processing certificate: {e}")

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

                self.debug(f"Checking for {fqdn} in certificate subject")
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
                self.error(f"Error processing certificate: {e}")
                ret['certerror'] = True

        return ret

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
            if noLog:
                self.debug(f"Fetching (HEAD): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
            else:
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
                if noLog:
                    self.debug(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {url}", exc_info=True)
                else:
                    self.error(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {url}", exc_info=True)

                return result

            size = int(hdr.headers.get('content-length', 0))
            newloc = hdr.headers.get('location', url).strip()

            # Relative re-direct
            if newloc.startswith("/") or newloc.startswith("../"):
                newloc = SpiderFootHelpers.urlBaseUrl(url) + newloc
            result['realurl'] = newloc
            result['code'] = str(hdr.status_code)

            if headOnly:
                return result

            if size > sizeLimit:
                return result

            if result['realurl'] != url:
                if noLog:
                    self.debug(f"Fetching (HEAD): {self.removeUrlCreds(result['realurl'])} ({', '.join(request_log)})")
                else:
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
                    if noLog:
                        self.debug(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {result['realurl']}", exc_info=True)
                    else:
                        self.error(f"Unexpected exception ({e}) occurred fetching (HEAD only) URL: {result['realurl']}", exc_info=True)

                    return result

        try:
            if postData:
                if noLog:
                    self.debug(f"Fetching (POST): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
                else:
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
                if noLog:
                    self.debug(f"Fetching (GET): {self.removeUrlCreds(url)} ({', '.join(request_log)})")
                else:
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
        except requests.exceptions.RequestException as e:
            self.error(f"Failed to connect to {url}: {e}")
            return result
        except Exception as e:
            if noLog:
                self.debug(f"Unexpected exception ({e}) occurred fetching URL: {url}", exc_info=True)
            else:
                self.error(f"Unexpected exception ({e}) occurred fetching URL: {url}", exc_info=True)

            return result

        try:
            result['headers'] = dict()
            result['realurl'] = res.url
            result['code'] = str(res.status_code)

            for header, value in res.headers.items():
                result['headers'][str(header).lower()] = str(value)

            # Sometimes content exceeds the size limit after decompression
            if sizeLimit and len(res.content) > sizeLimit:
                self.debug(f"Content exceeded size limit ({sizeLimit}), so returning no data just headers")
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

        except Exception as e:
            self.error(f"Unexpected exception ({e}) occurred parsing response for URL: {url}", exc_info=True)
            result['content'] = None
            result['status'] = str(e)

        atime = time.time()
        t = str(atime - btime)
        self.info(f"Fetched {self.removeUrlCreds(url)} ({len(result['content'] or '')} bytes in {t}s)")
        return result

    def checkDnsWildcard(self, target: str) -> bool:
        """Check if wildcard DNS is enabled for a domain by looking up a random subdomain.

        Args:
            target (str): domain

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

    def cveInfo(self, cveId: str, sources: str = "circl,nist") -> (str, str):
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

        def cveRating(score: int) -> str:
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
                        if data['result']['CVE_Items'][0]['impact'].get('baseMetricV3'):
                            score = data['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
                        else:
                            score = data['result']['CVE_Items'][0]['impact']['baseMetricV2']['cvssV2']['baseScore']
                        rating = cveRating(score)
                        if rating:
                            eventType = f"VULNERABILITY_CVE_{rating}"
                    except Exception:
                        score = "Unknown"

                    try:
                        descr = data['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
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
            searchString (str): Google search query
            opts (dict): TBD

        Returns:
            dict: Search results as {"webSearchUrl": "URL", "urls": [results]}
        """
        if not searchString:
            return None

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

    def bingIterate(self, searchString: str, opts: dict = None) -> dict:
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
            searchString (str): Bing search query
            opts (dict): TBD

        Returns:
            dict: Search results as {"webSearchUrl": "URL", "urls": [results]}
        """
        if not searchString:
            return None

        if opts is None:
            opts = {}

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
