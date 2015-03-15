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

import struct

import dns.exception
import dns.rdata
import dns.name

class SOA(dns.rdata.Rdata):
    """SOA record

    @ivar mname: the SOA MNAME (master name) field
    @type mname: dns.name.Name object
    @ivar rname: the SOA RNAME (responsible name) field
    @type rname: dns.name.Name object
    @ivar serial: The zone's serial number
    @type serial: int
    @ivar refresh: The zone's refresh value (in seconds)
    @type refresh: int
    @ivar retry: The zone's retry value (in seconds)
    @type retry: int
    @ivar expire: The zone's expiration value (in seconds)
    @type expire: int
    @ivar minimum: The zone's negative caching time (in seconds, called
    "minimum" for historical reasons)
    @type minimum: int
    @see: RFC 1035"""

    __slots__ = ['mname', 'rname', 'serial', 'refresh', 'retry', 'expire',
                 'minimum']

    def __init__(self, rdclass, rdtype, mname, rname, serial, refresh, retry,
                 expire, minimum):
        super(SOA, self).__init__(rdclass, rdtype)
        self.mname = mname
        self.rname = rname
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.minimum = minimum

    def to_text(self, origin=None, relativize=True, **kw):
        mname = self.mname.choose_relativity(origin, relativize)
        rname = self.rname.choose_relativity(origin, relativize)
        return '%s %s %d %d %d %d %d' % (
            mname, rname, self.serial, self.refresh, self.retry,
            self.expire, self.minimum )

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        mname = tok.get_name()
        rname = tok.get_name()
        mname = mname.choose_relativity(origin, relativize)
        rname = rname.choose_relativity(origin, relativize)
        serial = tok.get_uint32()
        refresh = tok.get_ttl()
        retry = tok.get_ttl()
        expire = tok.get_ttl()
        minimum = tok.get_ttl()
        tok.get_eol()
        return cls(rdclass, rdtype, mname, rname, serial, refresh, retry,
                   expire, minimum )

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        self.mname.to_wire(file, compress, origin)
        self.rname.to_wire(file, compress, origin)
        five_ints = struct.pack('!IIIII', self.serial, self.refresh,
                                self.retry, self.expire, self.minimum)
        file.write(five_ints)

    def to_digestable(self, origin = None):
        return self.mname.to_digestable(origin) + \
            self.rname.to_digestable(origin) + \
            struct.pack('!IIIII', self.serial, self.refresh,
                        self.retry, self.expire, self.minimum)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        (mname, cused) = dns.name.from_wire(wire[: current + rdlen], current)
        current += cused
        rdlen -= cused
        (rname, cused) = dns.name.from_wire(wire[: current + rdlen], current)
        current += cused
        rdlen -= cused
        if rdlen != 20:
            raise dns.exception.FormError
        five_ints = struct.unpack('!IIIII',
                                  wire[current : current + rdlen])
        if not origin is None:
            mname = mname.relativize(origin)
            rname = rname.relativize(origin)
        return cls(rdclass, rdtype, mname, rname,
                   five_ints[0], five_ints[1], five_ints[2], five_ints[3],
                   five_ints[4])

    from_wire = classmethod(from_wire)

    def choose_relativity(self, origin = None, relativize = True):
        self.mname = self.mname.choose_relativity(origin, relativize)
        self.rname = self.rname.choose_relativity(origin, relativize)

    def _cmp(self, other):
        v = cmp(self.mname, other.mname)
        if v == 0:
            v = cmp(self.rname, other.rname)
            if v == 0:
                self_ints = struct.pack('!IIIII', self.serial, self.refresh,
                                        self.retry, self.expire, self.minimum)
                other_ints = struct.pack('!IIIII', other.serial, other.refresh,
                                         other.retry, other.expire,
                                         other.minimum)
                v = cmp(self_ints, other_ints)
        return v
