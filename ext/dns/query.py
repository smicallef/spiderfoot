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

"""Talk to a DNS server."""

from __future__ import generators

import errno
import select
import socket
import struct
import sys
import time

import dns.exception
import dns.inet
import dns.name
import dns.message
import dns.rdataclass
import dns.rdatatype

class UnexpectedSource(dns.exception.DNSException):
    """Raised if a query response comes from an unexpected address or port."""
    pass

class BadResponse(dns.exception.FormError):
    """Raised if a query response does not respond to the question asked."""
    pass

def _compute_expiration(timeout):
    if timeout is None:
        return None
    else:
        return time.time() + timeout

def _poll_for(fd, readable, writable, error, timeout):
    """Poll polling backend.
    @param fd: File descriptor
    @type fd: int
    @param readable: Whether to wait for readability
    @type readable: bool
    @param writable: Whether to wait for writability
    @type writable: bool
    @param timeout: Deadline timeout (expiration time, in seconds)
    @type timeout: float
    @return True on success, False on timeout
    """
    event_mask = 0
    if readable:
        event_mask |= select.POLLIN
    if writable:
        event_mask |= select.POLLOUT
    if error:
        event_mask |= select.POLLERR

    pollable = select.poll()
    pollable.register(fd, event_mask)

    if timeout:
        event_list = pollable.poll(long(timeout * 1000))
    else:
        event_list = pollable.poll()

    return bool(event_list)

def _select_for(fd, readable, writable, error, timeout):
    """Select polling backend.
    @param fd: File descriptor
    @type fd: int
    @param readable: Whether to wait for readability
    @type readable: bool
    @param writable: Whether to wait for writability
    @type writable: bool
    @param timeout: Deadline timeout (expiration time, in seconds)
    @type timeout: float
    @return True on success, False on timeout
    """
    rset, wset, xset = [], [], []

    if readable:
        rset = [fd]
    if writable:
        wset = [fd]
    if error:
        xset = [fd]

    if timeout is None:
        (rcount, wcount, xcount) = select.select(rset, wset, xset)
    else:
        (rcount, wcount, xcount) = select.select(rset, wset, xset, timeout)

    return bool((rcount or wcount or xcount))

def _wait_for(fd, readable, writable, error, expiration):
    done = False
    while not done:
        if expiration is None:
            timeout = None
        else:
            timeout = expiration - time.time()
            if timeout <= 0.0:
                raise dns.exception.Timeout
        try:
            if not _polling_backend(fd, readable, writable, error, timeout):
                raise dns.exception.Timeout
        except select.error, e:
            if e.args[0] != errno.EINTR:
                raise e
        done = True

def _set_polling_backend(fn):
    """
    Internal API. Do not use.
    """
    global _polling_backend

    _polling_backend = fn

if hasattr(select, 'poll'):
    # Prefer poll() on platforms that support it because it has no
    # limits on the maximum value of a file descriptor (plus it will
    # be more efficient for high values).
    _polling_backend = _poll_for
else:
    _polling_backend = _select_for

def _wait_for_readable(s, expiration):
    _wait_for(s, True, False, True, expiration)

def _wait_for_writable(s, expiration):
    _wait_for(s, False, True, True, expiration)

def _addresses_equal(af, a1, a2):
    # Convert the first value of the tuple, which is a textual format
    # address into binary form, so that we are not confused by different
    # textual representations of the same address
    n1 = dns.inet.inet_pton(af, a1[0])
    n2 = dns.inet.inet_pton(af, a2[0])
    return n1 == n2 and a1[1:] == a2[1:]

def _destination_and_source(af, where, port, source, source_port):
    # Apply defaults and compute destination and source tuples
    # suitable for use in connect(), sendto(), or bind().
    if af is None:
        try:
            af = dns.inet.af_for_address(where)
        except:
            af = dns.inet.AF_INET
    if af == dns.inet.AF_INET:
        destination = (where, port)
        if source is not None or source_port != 0:
            if source is None:
                source = '0.0.0.0'
            source = (source, source_port)
    elif af == dns.inet.AF_INET6:
        destination = (where, port, 0, 0)
        if source is not None or source_port != 0:
            if source is None:
                source = '::'
            source = (source, source_port, 0, 0)
    return (af, destination, source)

def udp(q, where, timeout=None, port=53, af=None, source=None, source_port=0,
        ignore_unexpected=False, one_rr_per_rrset=False):
    """Return the response obtained after sending a query via UDP.

    @param q: the query
    @type q: dns.message.Message
    @param where: where to send the message
    @type where: string containing an IPv4 or IPv6 address
    @param timeout: The number of seconds to wait before the query times out.
    If None, the default, wait forever.
    @type timeout: float
    @param port: The port to which to send the message.  The default is 53.
    @type port: int
    @param af: the address family to use.  The default is None, which
    causes the address family to use to be inferred from the form of of where.
    If the inference attempt fails, AF_INET is used.
    @type af: int
    @rtype: dns.message.Message object
    @param source: source address.  The default is the wildcard address.
    @type source: string
    @param source_port: The port from which to send the message.
    The default is 0.
    @type source_port: int
    @param ignore_unexpected: If True, ignore responses from unexpected
    sources.  The default is False.
    @type ignore_unexpected: bool
    @param one_rr_per_rrset: Put each RR into its own RRset
    @type one_rr_per_rrset: bool
    """

    wire = q.to_wire()
    (af, destination, source) = _destination_and_source(af, where, port, source,
                                                        source_port)
    s = socket.socket(af, socket.SOCK_DGRAM, 0)
    try:
        expiration = _compute_expiration(timeout)
        s.setblocking(0)
        if source is not None:
            s.bind(source)
        _wait_for_writable(s, expiration)
        s.sendto(wire, destination)
        while 1:
            _wait_for_readable(s, expiration)
            (wire, from_address) = s.recvfrom(65535)
            if _addresses_equal(af, from_address, destination) or \
                    (dns.inet.is_multicast(where) and \
                         from_address[1:] == destination[1:]):
                break
            if not ignore_unexpected:
                raise UnexpectedSource('got a response from '
                                       '%s instead of %s' % (from_address,
                                                             destination))
    finally:
        s.close()
    r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                              one_rr_per_rrset=one_rr_per_rrset)
    if not q.is_response(r):
        raise BadResponse
    return r

def _net_read(sock, count, expiration):
    """Read the specified number of bytes from sock.  Keep trying until we
    either get the desired amount, or we hit EOF.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    s = ''
    while count > 0:
        _wait_for_readable(sock, expiration)
        n = sock.recv(count)
        if n == '':
            raise EOFError
        count = count - len(n)
        s = s + n
    return s

def _net_write(sock, data, expiration):
    """Write the specified data to the socket.
    A Timeout exception will be raised if the operation is not completed
    by the expiration time.
    """
    current = 0
    l = len(data)
    while current < l:
        _wait_for_writable(sock, expiration)
        current += sock.send(data[current:])

def _connect(s, address):
    try:
        s.connect(address)
    except socket.error:
        (ty, v) = sys.exc_info()[:2]
        if v[0] != errno.EINPROGRESS and \
               v[0] != errno.EWOULDBLOCK and \
               v[0] != errno.EALREADY:
            raise v

def tcp(q, where, timeout=None, port=53, af=None, source=None, source_port=0,
        one_rr_per_rrset=False):
    """Return the response obtained after sending a query via TCP.

    @param q: the query
    @type q: dns.message.Message object
    @param where: where to send the message
    @type where: string containing an IPv4 or IPv6 address
    @param timeout: The number of seconds to wait before the query times out.
    If None, the default, wait forever.
    @type timeout: float
    @param port: The port to which to send the message.  The default is 53.
    @type port: int
    @param af: the address family to use.  The default is None, which
    causes the address family to use to be inferred from the form of of where.
    If the inference attempt fails, AF_INET is used.
    @type af: int
    @rtype: dns.message.Message object
    @param source: source address.  The default is the wildcard address.
    @type source: string
    @param source_port: The port from which to send the message.
    The default is 0.
    @type source_port: int
    @param one_rr_per_rrset: Put each RR into its own RRset
    @type one_rr_per_rrset: bool
    """

    wire = q.to_wire()
    (af, destination, source) = _destination_and_source(af, where, port, source,
                                                        source_port)
    s = socket.socket(af, socket.SOCK_STREAM, 0)
    try:
        expiration = _compute_expiration(timeout)
        s.setblocking(0)
        if source is not None:
            s.bind(source)
        _connect(s, destination)

        l = len(wire)

        # copying the wire into tcpmsg is inefficient, but lets us
        # avoid writev() or doing a short write that would get pushed
        # onto the net
        tcpmsg = struct.pack("!H", l) + wire
        _net_write(s, tcpmsg, expiration)
        ldata = _net_read(s, 2, expiration)
        (l,) = struct.unpack("!H", ldata)
        wire = _net_read(s, l, expiration)
    finally:
        s.close()
    r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                              one_rr_per_rrset=one_rr_per_rrset)
    if not q.is_response(r):
        raise BadResponse
    return r

def xfr(where, zone, rdtype=dns.rdatatype.AXFR, rdclass=dns.rdataclass.IN,
        timeout=None, port=53, keyring=None, keyname=None, relativize=True,
        af=None, lifetime=None, source=None, source_port=0, serial=0,
        use_udp=False, keyalgorithm=dns.tsig.default_algorithm):
    """Return a generator for the responses to a zone transfer.

    @param where: where to send the message
    @type where: string containing an IPv4 or IPv6 address
    @param zone: The name of the zone to transfer
    @type zone: dns.name.Name object or string
    @param rdtype: The type of zone transfer.  The default is
    dns.rdatatype.AXFR.
    @type rdtype: int or string
    @param rdclass: The class of the zone transfer.  The default is
    dns.rdataclass.IN.
    @type rdclass: int or string
    @param timeout: The number of seconds to wait for each response message.
    If None, the default, wait forever.
    @type timeout: float
    @param port: The port to which to send the message.  The default is 53.
    @type port: int
    @param keyring: The TSIG keyring to use
    @type keyring: dict
    @param keyname: The name of the TSIG key to use
    @type keyname: dns.name.Name object or string
    @param relativize: If True, all names in the zone will be relativized to
    the zone origin.  It is essential that the relativize setting matches
    the one specified to dns.zone.from_xfr().
    @type relativize: bool
    @param af: the address family to use.  The default is None, which
    causes the address family to use to be inferred from the form of of where.
    If the inference attempt fails, AF_INET is used.
    @type af: int
    @param lifetime: The total number of seconds to spend doing the transfer.
    If None, the default, then there is no limit on the time the transfer may
    take.
    @type lifetime: float
    @rtype: generator of dns.message.Message objects.
    @param source: source address.  The default is the wildcard address.
    @type source: string
    @param source_port: The port from which to send the message.
    The default is 0.
    @type source_port: int
    @param serial: The SOA serial number to use as the base for an IXFR diff
    sequence (only meaningful if rdtype == dns.rdatatype.IXFR).
    @type serial: int
    @param use_udp: Use UDP (only meaningful for IXFR)
    @type use_udp: bool
    @param keyalgorithm: The TSIG algorithm to use; defaults to
    dns.tsig.default_algorithm
    @type keyalgorithm: string
    """

    if isinstance(zone, (str, unicode)):
        zone = dns.name.from_text(zone)
    if isinstance(rdtype, (str, unicode)):
        rdtype = dns.rdatatype.from_text(rdtype)
    q = dns.message.make_query(zone, rdtype, rdclass)
    if rdtype == dns.rdatatype.IXFR:
        rrset = dns.rrset.from_text(zone, 0, 'IN', 'SOA',
                                    '. . %u 0 0 0 0' % serial)
        q.authority.append(rrset)
    if not keyring is None:
        q.use_tsig(keyring, keyname, algorithm=keyalgorithm)
    wire = q.to_wire()
    (af, destination, source) = _destination_and_source(af, where, port, source,
                                                        source_port)
    if use_udp:
        if rdtype != dns.rdatatype.IXFR:
            raise ValueError('cannot do a UDP AXFR')
        s = socket.socket(af, socket.SOCK_DGRAM, 0)
    else:
        s = socket.socket(af, socket.SOCK_STREAM, 0)
    s.setblocking(0)
    if source is not None:
        s.bind(source)
    expiration = _compute_expiration(lifetime)
    _connect(s, destination)
    l = len(wire)
    if use_udp:
        _wait_for_writable(s, expiration)
        s.send(wire)
    else:
        tcpmsg = struct.pack("!H", l) + wire
        _net_write(s, tcpmsg, expiration)
    done = False
    soa_rrset = None
    soa_count = 0
    if relativize:
        origin = zone
        oname = dns.name.empty
    else:
        origin = None
        oname = zone
    tsig_ctx = None
    first = True
    while not done:
        mexpiration = _compute_expiration(timeout)
        if mexpiration is None or mexpiration > expiration:
            mexpiration = expiration
        if use_udp:
            _wait_for_readable(s, expiration)
            (wire, from_address) = s.recvfrom(65535)
        else:
            ldata = _net_read(s, 2, mexpiration)
            (l,) = struct.unpack("!H", ldata)
            wire = _net_read(s, l, mexpiration)
        r = dns.message.from_wire(wire, keyring=q.keyring, request_mac=q.mac,
                                  xfr=True, origin=origin, tsig_ctx=tsig_ctx,
                                  multi=True, first=first,
                                  one_rr_per_rrset=(rdtype==dns.rdatatype.IXFR))
        tsig_ctx = r.tsig_ctx
        first = False
        answer_index = 0
        delete_mode = False
        expecting_SOA = False
        if soa_rrset is None:
            if not r.answer or r.answer[0].name != oname:
                raise dns.exception.FormError
            rrset = r.answer[0]
            if rrset.rdtype != dns.rdatatype.SOA:
                raise dns.exception.FormError("first RRset is not an SOA")
            answer_index = 1
            soa_rrset = rrset.copy()
            if rdtype == dns.rdatatype.IXFR:
                if soa_rrset[0].serial == serial:
                    #
                    # We're already up-to-date.
                    #
                    done = True
                else:
                    expecting_SOA = True
        #
        # Process SOAs in the answer section (other than the initial
        # SOA in the first message).
        #
        for rrset in r.answer[answer_index:]:
            if done:
                raise dns.exception.FormError("answers after final SOA")
            if rrset.rdtype == dns.rdatatype.SOA and rrset.name == oname:
                if expecting_SOA:
                    if rrset[0].serial != serial:
                        raise dns.exception.FormError("IXFR base serial mismatch")
                    expecting_SOA = False
                elif rdtype == dns.rdatatype.IXFR:
                    delete_mode = not delete_mode
                if rrset == soa_rrset and not delete_mode:
                    done = True
            elif expecting_SOA:
                #
                # We made an IXFR request and are expecting another
                # SOA RR, but saw something else, so this must be an
                # AXFR response.
                #
                rdtype = dns.rdatatype.AXFR
                expecting_SOA = False
        if done and q.keyring and not r.had_tsig:
            raise dns.exception.FormError("missing TSIG")
        yield r
    s.close()
