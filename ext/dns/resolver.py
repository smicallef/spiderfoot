# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""DNS stub resolver.

@var default_resolver: The default resolver object
@type default_resolver: dns.resolver.Resolver object"""

import socket
import sys
import time

try:
    import threading as _threading
except ImportError:
    import dummy_threading as _threading

import dns.exception
import dns.flags
import dns.ipv4
import dns.ipv6
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.reversename

if sys.platform == 'win32':
    import _winreg

class NXDOMAIN(dns.exception.DNSException):
    """The query name does not exist."""
    pass

class YXDOMAIN(dns.exception.DNSException):
    """The query name is too long after DNAME substitution."""
    pass

# The definition of the Timeout exception has moved from here to the
# dns.exception module.  We keep dns.resolver.Timeout defined for
# backwards compatibility.

Timeout = dns.exception.Timeout

class NoAnswer(dns.exception.DNSException):
    """The response did not contain an answer to the question."""
    pass

class NoNameservers(dns.exception.DNSException):
    """No non-broken nameservers are available to answer the query."""
    pass

class NotAbsolute(dns.exception.DNSException):
    """Raised if an absolute domain name is required but a relative name
    was provided."""
    pass

class NoRootSOA(dns.exception.DNSException):
    """Raised if for some reason there is no SOA at the root name.
    This should never happen!"""
    pass

class NoMetaqueries(dns.exception.DNSException):
    """Metaqueries are not allowed."""
    pass


class Answer(object):
    """DNS stub resolver answer

    Instances of this class bundle up the result of a successful DNS
    resolution.

    For convenience, the answer object implements much of the sequence
    protocol, forwarding to its rrset.  E.g. "for a in answer" is
    equivalent to "for a in answer.rrset", "answer[i]" is equivalent
    to "answer.rrset[i]", and "answer[i:j]" is equivalent to
    "answer.rrset[i:j]".

    Note that CNAMEs or DNAMEs in the response may mean that answer
    node's name might not be the query name.

    @ivar qname: The query name
    @type qname: dns.name.Name object
    @ivar rdtype: The query type
    @type rdtype: int
    @ivar rdclass: The query class
    @type rdclass: int
    @ivar response: The response message
    @type response: dns.message.Message object
    @ivar rrset: The answer
    @type rrset: dns.rrset.RRset object
    @ivar expiration: The time when the answer expires
    @type expiration: float (seconds since the epoch)
    @ivar canonical_name: The canonical name of the query name
    @type canonical_name: dns.name.Name object
    """
    def __init__(self, qname, rdtype, rdclass, response,
                 raise_on_no_answer=True):
        self.qname = qname
        self.rdtype = rdtype
        self.rdclass = rdclass
        self.response = response
        min_ttl = -1
        rrset = None
        for count in xrange(0, 15):
            try:
                rrset = response.find_rrset(response.answer, qname,
                                            rdclass, rdtype)
                if min_ttl == -1 or rrset.ttl < min_ttl:
                    min_ttl = rrset.ttl
                break
            except KeyError:
                if rdtype != dns.rdatatype.CNAME:
                    try:
                        crrset = response.find_rrset(response.answer,
                                                     qname,
                                                     rdclass,
                                                     dns.rdatatype.CNAME)
                        if min_ttl == -1 or crrset.ttl < min_ttl:
                            min_ttl = crrset.ttl
                        for rd in crrset:
                            qname = rd.target
                            break
                        continue
                    except KeyError:
                        if raise_on_no_answer:
                            raise NoAnswer
                if raise_on_no_answer:
                    raise NoAnswer
        if rrset is None and raise_on_no_answer:
            raise NoAnswer
        self.canonical_name = qname
        self.rrset = rrset
        if rrset is None:
            while 1:
                # Look for a SOA RR whose owner name is a superdomain
                # of qname.
                try:
                    srrset = response.find_rrset(response.authority, qname,
                                                rdclass, dns.rdatatype.SOA)
                    if min_ttl == -1 or srrset.ttl < min_ttl:
                        min_ttl = srrset.ttl
                    if srrset[0].minimum < min_ttl:
                        min_ttl = srrset[0].minimum
                    break
                except KeyError:
                    try:
                        qname = qname.parent()
                    except dns.name.NoParent:
                        break
        self.expiration = time.time() + min_ttl

    def __getattr__(self, attr):
        if attr == 'name':
            return self.rrset.name
        elif attr == 'ttl':
            return self.rrset.ttl
        elif attr == 'covers':
            return self.rrset.covers
        elif attr == 'rdclass':
            return self.rrset.rdclass
        elif attr == 'rdtype':
            return self.rrset.rdtype
        else:
            raise AttributeError(attr)

    def __len__(self):
        return len(self.rrset)

    def __iter__(self):
        return iter(self.rrset)

    def __getitem__(self, i):
        return self.rrset[i]

    def __delitem__(self, i):
        del self.rrset[i]

    def __getslice__(self, i, j):
        return self.rrset[i:j]

    def __delslice__(self, i, j):
        del self.rrset[i:j]

class Cache(object):
    """Simple DNS answer cache.

    @ivar data: A dictionary of cached data
    @type data: dict
    @ivar cleaning_interval: The number of seconds between cleanings.  The
    default is 300 (5 minutes).
    @type cleaning_interval: float
    @ivar next_cleaning: The time the cache should next be cleaned (in seconds
    since the epoch.)
    @type next_cleaning: float
    """

    def __init__(self, cleaning_interval=300.0):
        """Initialize a DNS cache.

        @param cleaning_interval: the number of seconds between periodic
        cleanings.  The default is 300.0
        @type cleaning_interval: float.
        """

        self.data = {}
        self.cleaning_interval = cleaning_interval
        self.next_cleaning = time.time() + self.cleaning_interval
        self.lock = _threading.Lock()

    def _maybe_clean(self):
        """Clean the cache if it's time to do so."""

        now = time.time()
        if self.next_cleaning <= now:
            keys_to_delete = []
            for (k, v) in self.data.iteritems():
                if v.expiration <= now:
                    keys_to_delete.append(k)
            for k in keys_to_delete:
                del self.data[k]
            now = time.time()
            self.next_cleaning = now + self.cleaning_interval

    def get(self, key):
        """Get the answer associated with I{key}.  Returns None if
        no answer is cached for the key.
        @param key: the key
        @type key: (dns.name.Name, int, int) tuple whose values are the
        query name, rdtype, and rdclass.
        @rtype: dns.resolver.Answer object or None
        """

        try:
            self.lock.acquire()
            self._maybe_clean()
            v = self.data.get(key)
            if v is None or v.expiration <= time.time():
                return None
            return v
        finally:
            self.lock.release()

    def put(self, key, value):
        """Associate key and value in the cache.
        @param key: the key
        @type key: (dns.name.Name, int, int) tuple whose values are the
        query name, rdtype, and rdclass.
        @param value: The answer being cached
        @type value: dns.resolver.Answer object
        """

        try:
            self.lock.acquire()
            self._maybe_clean()
            self.data[key] = value
        finally:
            self.lock.release()

    def flush(self, key=None):
        """Flush the cache.

        If I{key} is specified, only that item is flushed.  Otherwise
        the entire cache is flushed.

        @param key: the key to flush
        @type key: (dns.name.Name, int, int) tuple or None
        """

        try:
            self.lock.acquire()
            if not key is None:
                if self.data.has_key(key):
                    del self.data[key]
            else:
                self.data = {}
                self.next_cleaning = time.time() + self.cleaning_interval
        finally:
            self.lock.release()

class LRUCacheNode(object):
    """LRUCache node.
    """
    def __init__(self, key, value):
        self.key = key
        self.value = value
        self.prev = self
        self.next = self

    def link_before(self, node):
        self.prev = node.prev
        self.next = node
        node.prev.next = self
        node.prev = self

    def link_after(self, node):
        self.prev = node
        self.next = node.next
        node.next.prev = self
        node.next = self

    def unlink(self):
        self.next.prev = self.prev
        self.prev.next = self.next

class LRUCache(object):
    """Bounded least-recently-used DNS answer cache.

    This cache is better than the simple cache (above) if you're
    running a web crawler or other process that does a lot of
    resolutions.  The LRUCache has a maximum number of nodes, and when
    it is full, the least-recently used node is removed to make space
    for a new one.

    @ivar data: A dictionary of cached data
    @type data: dict
    @ivar sentinel: sentinel node for circular doubly linked list of nodes
    @type sentinel: LRUCacheNode object
    @ivar max_size: The maximum number of nodes
    @type max_size: int
    """

    def __init__(self, max_size=100000):
        """Initialize a DNS cache.

        @param max_size: The maximum number of nodes to cache; the default is 100000.  Must be > 1.
        @type max_size: int
        """
        self.data = {}
        self.set_max_size(max_size)
        self.sentinel = LRUCacheNode(None, None)
        self.lock = _threading.Lock()

    def set_max_size(self, max_size):
        if max_size < 1:
            max_size = 1
        self.max_size = max_size

    def get(self, key):
        """Get the answer associated with I{key}.  Returns None if
        no answer is cached for the key.
        @param key: the key
        @type key: (dns.name.Name, int, int) tuple whose values are the
        query name, rdtype, and rdclass.
        @rtype: dns.resolver.Answer object or None
        """
        try:
            self.lock.acquire()
            node = self.data.get(key)
            if node is None:
                return None
            # Unlink because we're either going to move the node to the front
            # of the LRU list or we're going to free it.
            node.unlink()
            if node.value.expiration <= time.time():
                del self.data[node.key]
                return None
            node.link_after(self.sentinel)
            return node.value
        finally:
            self.lock.release()

    def put(self, key, value):
        """Associate key and value in the cache.
        @param key: the key
        @type key: (dns.name.Name, int, int) tuple whose values are the
        query name, rdtype, and rdclass.
        @param value: The answer being cached
        @type value: dns.resolver.Answer object
        """
        try:
            self.lock.acquire()
            node = self.data.get(key)
            if not node is None:
                node.unlink()
                del self.data[node.key]
            while len(self.data) >= self.max_size:
                node = self.sentinel.prev
                node.unlink()
                del self.data[node.key]
            node = LRUCacheNode(key, value)
            node.link_after(self.sentinel)
            self.data[key] = node
        finally:
            self.lock.release()

    def flush(self, key=None):
        """Flush the cache.

        If I{key} is specified, only that item is flushed.  Otherwise
        the entire cache is flushed.

        @param key: the key to flush
        @type key: (dns.name.Name, int, int) tuple or None
        """
        try:
            self.lock.acquire()
            if not key is None:
                node = self.data.get(key)
                if not node is None:
                    node.unlink()
                    del self.data[node.key]
            else:
                node = self.sentinel.next
                while node != self.sentinel:
                    next = node.next
                    node.prev = None
                    node.next = None
                    node = next
                self.data = {}
        finally:
            self.lock.release()

class Resolver(object):
    """DNS stub resolver

    @ivar domain: The domain of this host
    @type domain: dns.name.Name object
    @ivar nameservers: A list of nameservers to query.  Each nameserver is
    a string which contains the IP address of a nameserver.
    @type nameservers: list of strings
    @ivar search: The search list.  If the query name is a relative name,
    the resolver will construct an absolute query name by appending the search
    names one by one to the query name.
    @type search: list of dns.name.Name objects
    @ivar port: The port to which to send queries.  The default is 53.
    @type port: int
    @ivar timeout: The number of seconds to wait for a response from a
    server, before timing out.
    @type timeout: float
    @ivar lifetime: The total number of seconds to spend trying to get an
    answer to the question.  If the lifetime expires, a Timeout exception
    will occur.
    @type lifetime: float
    @ivar keyring: The TSIG keyring to use.  The default is None.
    @type keyring: dict
    @ivar keyname: The TSIG keyname to use.  The default is None.
    @type keyname: dns.name.Name object
    @ivar keyalgorithm: The TSIG key algorithm to use.  The default is
    dns.tsig.default_algorithm.
    @type keyalgorithm: string
    @ivar edns: The EDNS level to use.  The default is -1, no Edns.
    @type edns: int
    @ivar ednsflags: The EDNS flags
    @type ednsflags: int
    @ivar payload: The EDNS payload size.  The default is 0.
    @type payload: int
    @ivar flags: The message flags to use.  The default is None (i.e. not overwritten)
    @type flags: int
    @ivar cache: The cache to use.  The default is None.
    @type cache: dns.resolver.Cache object
    @ivar retry_servfail: should we retry a nameserver if it says SERVFAIL?
    The default is 'false'.
    @type retry_servfail: bool
    """
    def __init__(self, filename='/etc/resolv.conf', configure=True):
        """Initialize a resolver instance.

        @param filename: The filename of a configuration file in
        standard /etc/resolv.conf format.  This parameter is meaningful
        only when I{configure} is true and the platform is POSIX.
        @type filename: string or file object
        @param configure: If True (the default), the resolver instance
        is configured in the normal fashion for the operating system
        the resolver is running on.  (I.e. a /etc/resolv.conf file on
        POSIX systems and from the registry on Windows systems.)
        @type configure: bool"""

        self.reset()
        if configure:
            if sys.platform == 'win32':
                self.read_registry()
            elif filename:
                self.read_resolv_conf(filename)

    def reset(self):
        """Reset all resolver configuration to the defaults."""
        self.domain = \
            dns.name.Name(dns.name.from_text(socket.gethostname())[1:])
        if len(self.domain) == 0:
            self.domain = dns.name.root
        self.nameservers = []
        self.search = []
        self.port = 53
        self.timeout = 2.0
        self.lifetime = 30.0
        self.keyring = None
        self.keyname = None
        self.keyalgorithm = dns.tsig.default_algorithm
        self.edns = -1
        self.ednsflags = 0
        self.payload = 0
        self.cache = None
        self.flags = None
        self.retry_servfail = False

    def read_resolv_conf(self, f):
        """Process f as a file in the /etc/resolv.conf format.  If f is
        a string, it is used as the name of the file to open; otherwise it
        is treated as the file itself."""
        if isinstance(f, str) or isinstance(f, unicode):
            try:
                f = open(f, 'r')
            except IOError:
                # /etc/resolv.conf doesn't exist, can't be read, etc.
                # We'll just use the default resolver configuration.
                self.nameservers = ['127.0.0.1']
                return
            want_close = True
        else:
            want_close = False
        try:
            for l in f:
                if len(l) == 0 or l[0] == '#' or l[0] == ';':
                    continue
                tokens = l.split()
                if len(tokens) == 0:
                    continue
                if tokens[0] == 'nameserver':
                    self.nameservers.append(tokens[1])
                elif tokens[0] == 'domain':
                    self.domain = dns.name.from_text(tokens[1])
                elif tokens[0] == 'search':
                    for suffix in tokens[1:]:
                        self.search.append(dns.name.from_text(suffix))
        finally:
            if want_close:
                f.close()
        if len(self.nameservers) == 0:
            self.nameservers.append('127.0.0.1')

    def _determine_split_char(self, entry):
        #
        # The windows registry irritatingly changes the list element
        # delimiter in between ' ' and ',' (and vice-versa) in various
        # versions of windows.
        #
        if entry.find(' ') >= 0:
            split_char = ' '
        elif entry.find(',') >= 0:
            split_char = ','
        else:
            # probably a singleton; treat as a space-separated list.
            split_char = ' '
        return split_char

    def _config_win32_nameservers(self, nameservers):
        """Configure a NameServer registry entry."""
        # we call str() on nameservers to convert it from unicode to ascii
        nameservers = str(nameservers)
        split_char = self._determine_split_char(nameservers)
        ns_list = nameservers.split(split_char)
        for ns in ns_list:
            if not ns in self.nameservers:
                self.nameservers.append(ns)

    def _config_win32_domain(self, domain):
        """Configure a Domain registry entry."""
        # we call str() on domain to convert it from unicode to ascii
        self.domain = dns.name.from_text(str(domain))

    def _config_win32_search(self, search):
        """Configure a Search registry entry."""
        # we call str() on search to convert it from unicode to ascii
        search = str(search)
        split_char = self._determine_split_char(search)
        search_list = search.split(split_char)
        for s in search_list:
            if not s in self.search:
                self.search.append(dns.name.from_text(s))

    def _config_win32_fromkey(self, key):
        """Extract DNS info from a registry key."""
        try:
            servers, rtype = _winreg.QueryValueEx(key, 'NameServer')
        except WindowsError:
            servers = None
        if servers:
            self._config_win32_nameservers(servers)
            try:
                dom, rtype = _winreg.QueryValueEx(key, 'Domain')
                if dom:
                    self._config_win32_domain(dom)
            except WindowsError:
                pass
        else:
            try:
                servers, rtype = _winreg.QueryValueEx(key, 'DhcpNameServer')
            except WindowsError:
                servers = None
            if servers:
                self._config_win32_nameservers(servers)
                try:
                    dom, rtype = _winreg.QueryValueEx(key, 'DhcpDomain')
                    if dom:
                        self._config_win32_domain(dom)
                except WindowsError:
                    pass
        try:
            search, rtype = _winreg.QueryValueEx(key, 'SearchList')
        except WindowsError:
            search = None
        if search:
            self._config_win32_search(search)

    def read_registry(self):
        """Extract resolver configuration from the Windows registry."""
        lm = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
        want_scan = False
        try:
            try:
                # XP, 2000
                tcp_params = _winreg.OpenKey(lm,
                                             r'SYSTEM\CurrentControlSet'
                                             r'\Services\Tcpip\Parameters')
                want_scan = True
            except EnvironmentError:
                # ME
                tcp_params = _winreg.OpenKey(lm,
                                             r'SYSTEM\CurrentControlSet'
                                             r'\Services\VxD\MSTCP')
            try:
                self._config_win32_fromkey(tcp_params)
            finally:
                tcp_params.Close()
            if want_scan:
                interfaces = _winreg.OpenKey(lm,
                                             r'SYSTEM\CurrentControlSet'
                                             r'\Services\Tcpip\Parameters'
                                             r'\Interfaces')
                try:
                    i = 0
                    while True:
                        try:
                            guid = _winreg.EnumKey(interfaces, i)
                            i += 1
                            key = _winreg.OpenKey(interfaces, guid)
                            if not self._win32_is_nic_enabled(lm, guid, key):
                                continue
                            try:
                                self._config_win32_fromkey(key)
                            finally:
                                key.Close()
                        except EnvironmentError:
                            break
                finally:
                    interfaces.Close()
        finally:
            lm.Close()

    def _win32_is_nic_enabled(self, lm, guid, interface_key):
         # Look in the Windows Registry to determine whether the network
         # interface corresponding to the given guid is enabled.
         #
         # (Code contributed by Paul Marks, thanks!)
         #
         try:
             # This hard-coded location seems to be consistent, at least
             # from Windows 2000 through Vista.
             connection_key = _winreg.OpenKey(
                 lm,
                 r'SYSTEM\CurrentControlSet\Control\Network'
                 r'\{4D36E972-E325-11CE-BFC1-08002BE10318}'
                 r'\%s\Connection' % guid)

             try:
                 # The PnpInstanceID points to a key inside Enum
                 (pnp_id, ttype) = _winreg.QueryValueEx(
                     connection_key, 'PnpInstanceID')

                 if ttype != _winreg.REG_SZ:
                     raise ValueError

                 device_key = _winreg.OpenKey(
                     lm, r'SYSTEM\CurrentControlSet\Enum\%s' % pnp_id)

                 try:
                     # Get ConfigFlags for this device
                     (flags, ttype) = _winreg.QueryValueEx(
                         device_key, 'ConfigFlags')

                     if ttype != _winreg.REG_DWORD:
                         raise ValueError

                     # Based on experimentation, bit 0x1 indicates that the
                     # device is disabled.
                     return not (flags & 0x1)

                 finally:
                     device_key.Close()
             finally:
                 connection_key.Close()
         except (EnvironmentError, ValueError):
             # Pre-vista, enabled interfaces seem to have a non-empty
             # NTEContextList; this was how dnspython detected enabled
             # nics before the code above was contributed.  We've retained
             # the old method since we don't know if the code above works
             # on Windows 95/98/ME.
             try:
                 (nte, ttype) = _winreg.QueryValueEx(interface_key,
                                                     'NTEContextList')
                 return nte is not None
             except WindowsError:
                 return False

    def _compute_timeout(self, start):
        now = time.time()
        if now < start:
            if start - now > 1:
                # Time going backwards is bad.  Just give up.
                raise Timeout
            else:
                # Time went backwards, but only a little.  This can
                # happen, e.g. under vmware with older linux kernels.
                # Pretend it didn't happen.
                now = start
        duration = now - start
        if duration >= self.lifetime:
            raise Timeout
        return min(self.lifetime - duration, self.timeout)

    def query(self, qname, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN,
              tcp=False, source=None, raise_on_no_answer=True, source_port=0):
        """Query nameservers to find the answer to the question.

        The I{qname}, I{rdtype}, and I{rdclass} parameters may be objects
        of the appropriate type, or strings that can be converted into objects
        of the appropriate type.  E.g. For I{rdtype} the integer 2 and the
        the string 'NS' both mean to query for records with DNS rdata type NS.

        @param qname: the query name
        @type qname: dns.name.Name object or string
        @param rdtype: the query type
        @type rdtype: int or string
        @param rdclass: the query class
        @type rdclass: int or string
        @param tcp: use TCP to make the query (default is False).
        @type tcp: bool
        @param source: bind to this IP address (defaults to machine default IP).
        @type source: IP address in dotted quad notation
        @param raise_on_no_answer: raise NoAnswer if there's no answer
        (defaults is True).
        @type raise_on_no_answer: bool
        @param source_port: The port from which to send the message.
        The default is 0.
        @type source_port: int
        @rtype: dns.resolver.Answer instance
        @raises Timeout: no answers could be found in the specified lifetime
        @raises NXDOMAIN: the query name does not exist
        @raises YXDOMAIN: the query name is too long after DNAME substitution
        @raises NoAnswer: the response did not contain an answer and
        raise_on_no_answer is True.
        @raises NoNameservers: no non-broken nameservers are available to
        answer the question."""

        if isinstance(qname, (str, unicode)):
            qname = dns.name.from_text(qname, None)
        if isinstance(rdtype, (str, unicode)):
            rdtype = dns.rdatatype.from_text(rdtype)
        if dns.rdatatype.is_metatype(rdtype):
            raise NoMetaqueries
        if isinstance(rdclass, (str, unicode)):
            rdclass = dns.rdataclass.from_text(rdclass)
        if dns.rdataclass.is_metaclass(rdclass):
            raise NoMetaqueries
        qnames_to_try = []
        if qname.is_absolute():
            qnames_to_try.append(qname)
        else:
            if len(qname) > 1:
                qnames_to_try.append(qname.concatenate(dns.name.root))
            if self.search:
                for suffix in self.search:
                    qnames_to_try.append(qname.concatenate(suffix))
            else:
                qnames_to_try.append(qname.concatenate(self.domain))
        all_nxdomain = True
        start = time.time()
        for qname in qnames_to_try:
            if self.cache:
                answer = self.cache.get((qname, rdtype, rdclass))
                if not answer is None:
                    if answer.rrset is None and raise_on_no_answer:
                        raise NoAnswer
                    else:
                        return answer
            request = dns.message.make_query(qname, rdtype, rdclass)
            if not self.keyname is None:
                request.use_tsig(self.keyring, self.keyname,
                                 algorithm=self.keyalgorithm)
            request.use_edns(self.edns, self.ednsflags, self.payload)
            if self.flags is not None:
                request.flags = self.flags
            response = None
            #
            # make a copy of the servers list so we can alter it later.
            #
            nameservers = self.nameservers[:]
            backoff = 0.10
            while response is None:
                if len(nameservers) == 0:
                    raise NoNameservers
                for nameserver in nameservers[:]:
                    timeout = self._compute_timeout(start)
                    try:
                        if tcp:
                            response = dns.query.tcp(request, nameserver,
                                                     timeout, self.port,
                                                     source=source,
                                                     source_port=source_port)
                        else:
                            response = dns.query.udp(request, nameserver,
                                                     timeout, self.port,
                                                     source=source,
                                                     source_port=source_port)
                            if response.flags & dns.flags.TC:
                                # Response truncated; retry with TCP.
                                timeout = self._compute_timeout(start)
                                response = dns.query.tcp(request, nameserver,
                                                       timeout, self.port,
                                                       source=source,
                                                       source_port=source_port)
                    except (socket.error, dns.exception.Timeout):
                        #
                        # Communication failure or timeout.  Go to the
                        # next server
                        #
                        response = None
                        continue
                    except dns.query.UnexpectedSource:
                        #
                        # Who knows?  Keep going.
                        #
                        response = None
                        continue
                    except dns.exception.FormError:
                        #
                        # We don't understand what this server is
                        # saying.  Take it out of the mix and
                        # continue.
                        #
                        nameservers.remove(nameserver)
                        response = None
                        continue
                    except EOFError:
                        #
                        # We're using TCP and they hung up on us.
                        # Probably they don't support TCP (though
                        # they're supposed to!).  Take it out of the
                        # mix and continue.
                        #
                        nameservers.remove(nameserver)
                        response = None
                        continue
                    rcode = response.rcode()
                    if rcode == dns.rcode.YXDOMAIN:
                        raise YXDOMAIN
                    if rcode == dns.rcode.NOERROR or \
                           rcode == dns.rcode.NXDOMAIN:
                        break
                    #
                    # We got a response, but we're not happy with the
                    # rcode in it.  Remove the server from the mix if
                    # the rcode isn't SERVFAIL.
                    #
                    if rcode != dns.rcode.SERVFAIL or not self.retry_servfail:
                        nameservers.remove(nameserver)
                    response = None
                if not response is None:
                    break
                #
                # All nameservers failed!
                #
                if len(nameservers) > 0:
                    #
                    # But we still have servers to try.  Sleep a bit
                    # so we don't pound them!
                    #
                    timeout = self._compute_timeout(start)
                    sleep_time = min(timeout, backoff)
                    backoff *= 2
                    time.sleep(sleep_time)
            if response.rcode() == dns.rcode.NXDOMAIN:
                continue
            all_nxdomain = False
            break
        if all_nxdomain:
            raise NXDOMAIN
        answer = Answer(qname, rdtype, rdclass, response,
                        raise_on_no_answer)
        if self.cache:
            self.cache.put((qname, rdtype, rdclass), answer)
        return answer

    def use_tsig(self, keyring, keyname=None,
                 algorithm=dns.tsig.default_algorithm):
        """Add a TSIG signature to the query.

        @param keyring: The TSIG keyring to use; defaults to None.
        @type keyring: dict
        @param keyname: The name of the TSIG key to use; defaults to None.
        The key must be defined in the keyring.  If a keyring is specified
        but a keyname is not, then the key used will be the first key in the
        keyring.  Note that the order of keys in a dictionary is not defined,
        so applications should supply a keyname when a keyring is used, unless
        they know the keyring contains only one key.
        @param algorithm: The TSIG key algorithm to use.  The default
        is dns.tsig.default_algorithm.
        @type algorithm: string"""
        self.keyring = keyring
        if keyname is None:
            self.keyname = self.keyring.keys()[0]
        else:
            self.keyname = keyname
        self.keyalgorithm = algorithm

    def use_edns(self, edns, ednsflags, payload):
        """Configure Edns.

        @param edns: The EDNS level to use.  The default is -1, no Edns.
        @type edns: int
        @param ednsflags: The EDNS flags
        @type ednsflags: int
        @param payload: The EDNS payload size.  The default is 0.
        @type payload: int"""

        if edns is None:
            edns = -1
        self.edns = edns
        self.ednsflags = ednsflags
        self.payload = payload

    def set_flags(self, flags):
        """Overrides the default flags with your own

        @param flags: The flags to overwrite the default with
        @type flags: int"""
        self.flags = flags

default_resolver = None

def get_default_resolver():
    """Get the default resolver, initializing it if necessary."""
    global default_resolver
    if default_resolver is None:
        default_resolver = Resolver()
    return default_resolver

def query(qname, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN,
          tcp=False, source=None, raise_on_no_answer=True,
          source_port=0):
    """Query nameservers to find the answer to the question.

    This is a convenience function that uses the default resolver
    object to make the query.
    @see: L{dns.resolver.Resolver.query} for more information on the
    parameters."""
    return get_default_resolver().query(qname, rdtype, rdclass, tcp, source,
                                        raise_on_no_answer, source_port)

def zone_for_name(name, rdclass=dns.rdataclass.IN, tcp=False, resolver=None):
    """Find the name of the zone which contains the specified name.

    @param name: the query name
    @type name: absolute dns.name.Name object or string
    @param rdclass: The query class
    @type rdclass: int
    @param tcp: use TCP to make the query (default is False).
    @type tcp: bool
    @param resolver: the resolver to use
    @type resolver: dns.resolver.Resolver object or None
    @rtype: dns.name.Name"""

    if isinstance(name, (str, unicode)):
        name = dns.name.from_text(name, dns.name.root)
    if resolver is None:
        resolver = get_default_resolver()
    if not name.is_absolute():
        raise NotAbsolute(name)
    while 1:
        try:
            answer = resolver.query(name, dns.rdatatype.SOA, rdclass, tcp)
            if answer.rrset.name == name:
                return name
            # otherwise we were CNAMEd or DNAMEd and need to look higher
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        try:
            name = name.parent()
        except dns.name.NoParent:
            raise NoRootSOA

#
# Support for overriding the system resolver for all python code in the
# running process.
#

_protocols_for_socktype = {
    socket.SOCK_DGRAM : [socket.SOL_UDP],
    socket.SOCK_STREAM : [socket.SOL_TCP],
    }

_resolver = None
_original_getaddrinfo = socket.getaddrinfo
_original_getnameinfo = socket.getnameinfo
_original_getfqdn = socket.getfqdn
_original_gethostbyname = socket.gethostbyname
_original_gethostbyname_ex = socket.gethostbyname_ex
_original_gethostbyaddr = socket.gethostbyaddr

def _getaddrinfo(host=None, service=None, family=socket.AF_UNSPEC, socktype=0,
                 proto=0, flags=0):
    if flags & (socket.AI_ADDRCONFIG|socket.AI_V4MAPPED) != 0:
        raise NotImplementedError
    if host is None and service is None:
        raise socket.gaierror(socket.EAI_NONAME)
    v6addrs = []
    v4addrs = []
    canonical_name = None
    try:
        # Is host None or a V6 address literal?
        if host is None:
            canonical_name = 'localhost'
            if flags & socket.AI_PASSIVE != 0:
                v6addrs.append('::')
                v4addrs.append('0.0.0.0')
            else:
                v6addrs.append('::1')
                v4addrs.append('127.0.0.1')
        else:
            parts = host.split('%')
            if len(parts) == 2:
                ahost = parts[0]
            else:
                ahost = host
            addr = dns.ipv6.inet_aton(ahost)
            v6addrs.append(host)
            canonical_name = host
    except:
        try:
            # Is it a V4 address literal?
            addr = dns.ipv4.inet_aton(host)
            v4addrs.append(host)
            canonical_name = host
        except:
            if flags & socket.AI_NUMERICHOST == 0:
                try:
                    qname = None
                    if family == socket.AF_INET6 or family == socket.AF_UNSPEC:
                        v6 = _resolver.query(host, dns.rdatatype.AAAA,
                                             raise_on_no_answer=False)
                        # Note that setting host ensures we query the same name
                        # for A as we did for AAAA.
                        host = v6.qname
                        canonical_name = v6.canonical_name.to_text(True)
                        if v6.rrset is not None:
                            for rdata in v6.rrset:
                                v6addrs.append(rdata.address)
                    if family == socket.AF_INET or family == socket.AF_UNSPEC:
                        v4 = _resolver.query(host, dns.rdatatype.A,
                                             raise_on_no_answer=False)
                        host = v4.qname
                        canonical_name = v4.canonical_name.to_text(True)
                        if v4.rrset is not None:
                            for rdata in v4.rrset:
                                v4addrs.append(rdata.address)
                except dns.resolver.NXDOMAIN:
                    raise socket.gaierror(socket.EAI_NONAME)
                except:
                    raise socket.gaierror(socket.EAI_SYSTEM)
    port = None
    try:
        # Is it a port literal?
        if service is None:
            port = 0
        else:
            port = int(service)
    except:
        if flags & socket.AI_NUMERICSERV == 0:
            try:
                port = socket.getservbyname(service)
            except:
                pass
    if port is None:
        raise socket.gaierror(socket.EAI_NONAME)
    tuples = []
    if socktype == 0:
        socktypes = [socket.SOCK_DGRAM, socket.SOCK_STREAM]
    else:
        socktypes = [socktype]
    if flags & socket.AI_CANONNAME != 0:
        cname = canonical_name
    else:
        cname = ''
    if family == socket.AF_INET6 or family == socket.AF_UNSPEC:
        for addr in v6addrs:
            for socktype in socktypes:
                for proto in _protocols_for_socktype[socktype]:
                    tuples.append((socket.AF_INET6, socktype, proto,
                                   cname, (addr, port, 0, 0)))
    if family == socket.AF_INET or family == socket.AF_UNSPEC:
        for addr in v4addrs:
            for socktype in socktypes:
                for proto in _protocols_for_socktype[socktype]:
                    tuples.append((socket.AF_INET, socktype, proto,
                                   cname, (addr, port)))
    if len(tuples) == 0:
        raise socket.gaierror(socket.EAI_NONAME)
    return tuples

def _getnameinfo(sockaddr, flags=0):
    host = sockaddr[0]
    port = sockaddr[1]
    if len(sockaddr) == 4:
        scope = sockaddr[3]
        family = socket.AF_INET6
    else:
        scope = None
        family = socket.AF_INET
    tuples = _getaddrinfo(host, port, family, socket.SOCK_STREAM,
                          socket.SOL_TCP, 0)
    if len(tuples) > 1:
        raise socket.error('sockaddr resolved to multiple addresses')
    addr = tuples[0][4][0]
    if flags & socket.NI_DGRAM:
        pname = 'udp'
    else:
        pname = 'tcp'
    qname = dns.reversename.from_address(addr)
    if flags & socket.NI_NUMERICHOST == 0:
        try:
            answer = _resolver.query(qname, 'PTR')
            hostname = answer.rrset[0].target.to_text(True)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            if flags & socket.NI_NAMEREQD:
                raise socket.gaierror(socket.EAI_NONAME)
            hostname = addr
            if scope is not None:
                hostname += '%' + str(scope)
    else:
        hostname = addr
        if scope is not None:
            hostname += '%' + str(scope)
    if flags & socket.NI_NUMERICSERV:
        service = str(port)
    else:
        service = socket.getservbyport(port, pname)
    return (hostname, service)

def _getfqdn(name=None):
    if name is None:
        name = socket.gethostname()
    return _getnameinfo(_getaddrinfo(name, 80)[0][4])[0]

def _gethostbyname(name):
    return _gethostbyname_ex(name)[2][0]

def _gethostbyname_ex(name):
    aliases = []
    addresses = []
    tuples = _getaddrinfo(name, 0, socket.AF_INET, socket.SOCK_STREAM,
                         socket.SOL_TCP, socket.AI_CANONNAME)
    canonical = tuples[0][3]
    for item in tuples:
        addresses.append(item[4][0])
    # XXX we just ignore aliases
    return (canonical, aliases, addresses)

def _gethostbyaddr(ip):
    try:
        addr = dns.ipv6.inet_aton(ip)
        sockaddr = (ip, 80, 0, 0)
        family = socket.AF_INET6
    except:
        sockaddr = (ip, 80)
        family = socket.AF_INET
    (name, port) = _getnameinfo(sockaddr, socket.NI_NAMEREQD)
    aliases = []
    addresses = []
    tuples = _getaddrinfo(name, 0, family, socket.SOCK_STREAM, socket.SOL_TCP,
                          socket.AI_CANONNAME)
    canonical = tuples[0][3]
    for item in tuples:
        addresses.append(item[4][0])
    # XXX we just ignore aliases
    return (canonical, aliases, addresses)

def override_system_resolver(resolver=None):
    """Override the system resolver routines in the socket module with
    versions which use dnspython's resolver.

    This can be useful in testing situations where you want to control
    the resolution behavior of python code without having to change
    the system's resolver settings (e.g. /etc/resolv.conf).

    The resolver to use may be specified; if it's not, the default
    resolver will be used.

    @param resolver: the resolver to use
    @type resolver: dns.resolver.Resolver object or None
    """
    if resolver is None:
        resolver = get_default_resolver()
    global _resolver
    _resolver = resolver
    socket.getaddrinfo = _getaddrinfo
    socket.getnameinfo = _getnameinfo
    socket.getfqdn = _getfqdn
    socket.gethostbyname = _gethostbyname
    socket.gethostbyname_ex = _gethostbyname_ex
    socket.gethostbyaddr = _gethostbyaddr

def restore_system_resolver():
    """Undo the effects of override_system_resolver().
    """
    global _resolver
    _resolver = None
    socket.getaddrinfo = _original_getaddrinfo
    socket.getnameinfo = _original_getnameinfo
    socket.getfqdn = _original_getfqdn
    socket.gethostbyname = _original_gethostbyname
    socket.gethostbyname_ex = _original_gethostbyname_ex
    socket.gethostbyaddr = _original_gethostbyaddr
