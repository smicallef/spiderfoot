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

class PX(dns.rdata.Rdata):
    """PX record.

    @ivar preference: the preference value
    @type preference: int
    @ivar map822: the map822 name
    @type map822: dns.name.Name object
    @ivar mapx400: the mapx400 name
    @type mapx400: dns.name.Name object
    @see: RFC 2163"""

    __slots__ = ['preference', 'map822', 'mapx400']

    def __init__(self, rdclass, rdtype, preference, map822, mapx400):
        super(PX, self).__init__(rdclass, rdtype)
        self.preference = preference
        self.map822 = map822
        self.mapx400 = mapx400

    def to_text(self, origin=None, relativize=True, **kw):
        map822 = self.map822.choose_relativity(origin, relativize)
        mapx400 = self.mapx400.choose_relativity(origin, relativize)
        return '%d %s %s' % (self.preference, map822, mapx400)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        preference = tok.get_uint16()
        map822 = tok.get_name()
        map822 = map822.choose_relativity(origin, relativize)
        mapx400 = tok.get_name(None)
        mapx400 = mapx400.choose_relativity(origin, relativize)
        tok.get_eol()
        return cls(rdclass, rdtype, preference, map822, mapx400)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        pref = struct.pack("!H", self.preference)
        file.write(pref)
        self.map822.to_wire(file, None, origin)
        self.mapx400.to_wire(file, None, origin)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        (preference, ) = struct.unpack('!H', wire[current : current + 2])
        current += 2
        rdlen -= 2
        (map822, cused) = dns.name.from_wire(wire[: current + rdlen],
                                               current)
        if cused > rdlen:
            raise dns.exception.FormError
        current += cused
        rdlen -= cused
        if not origin is None:
            map822 = map822.relativize(origin)
        (mapx400, cused) = dns.name.from_wire(wire[: current + rdlen],
                                              current)
        if cused != rdlen:
            raise dns.exception.FormError
        if not origin is None:
            mapx400 = mapx400.relativize(origin)
        return cls(rdclass, rdtype, preference, map822, mapx400)

    from_wire = classmethod(from_wire)

    def choose_relativity(self, origin = None, relativize = True):
        self.map822 = self.map822.choose_relativity(origin, relativize)
        self.mapx400 = self.mapx400.choose_relativity(origin, relativize)

    def _cmp(self, other):
        sp = struct.pack("!H", self.preference)
        op = struct.pack("!H", other.preference)
        v = cmp(sp, op)
        if v == 0:
            v = cmp(self.map822, other.map822)
            if v == 0:
                v = cmp(self.mapx400, other.mapx400)
        return v
