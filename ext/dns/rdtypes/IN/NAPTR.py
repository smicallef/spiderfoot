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
import dns.name
import dns.rdata

def _write_string(file, s):
    l = len(s)
    assert l < 256
    byte = chr(l)
    file.write(byte)
    file.write(s)

class NAPTR(dns.rdata.Rdata):
    """NAPTR record

    @ivar order: order
    @type order: int
    @ivar preference: preference
    @type preference: int
    @ivar flags: flags
    @type flags: string
    @ivar service: service
    @type service: string
    @ivar regexp: regular expression
    @type regexp: string
    @ivar replacement: replacement name
    @type replacement: dns.name.Name object
    @see: RFC 3403"""

    __slots__ = ['order', 'preference', 'flags', 'service', 'regexp',
                 'replacement']

    def __init__(self, rdclass, rdtype, order, preference, flags, service,
                 regexp, replacement):
        super(NAPTR, self).__init__(rdclass, rdtype)
        self.order = order
        self.preference = preference
        self.flags = flags
        self.service = service
        self.regexp = regexp
        self.replacement = replacement

    def to_text(self, origin=None, relativize=True, **kw):
        replacement = self.replacement.choose_relativity(origin, relativize)
        return '%d %d "%s" "%s" "%s" %s' % \
               (self.order, self.preference,
                dns.rdata._escapify(self.flags),
                dns.rdata._escapify(self.service),
                dns.rdata._escapify(self.regexp),
                self.replacement)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        order = tok.get_uint16()
        preference = tok.get_uint16()
        flags = tok.get_string()
        service = tok.get_string()
        regexp = tok.get_string()
        replacement = tok.get_name()
        replacement = replacement.choose_relativity(origin, relativize)
        tok.get_eol()
        return cls(rdclass, rdtype, order, preference, flags, service,
                   regexp, replacement)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        two_ints = struct.pack("!HH", self.order, self.preference)
        file.write(two_ints)
        _write_string(file, self.flags)
        _write_string(file, self.service)
        _write_string(file, self.regexp)
        self.replacement.to_wire(file, compress, origin)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        (order, preference) = struct.unpack('!HH', wire[current : current + 4])
        current += 4
        rdlen -= 4
        strings = []
        for i in xrange(3):
            l = ord(wire[current])
            current += 1
            rdlen -= 1
            if l > rdlen or rdlen < 0:
                raise dns.exception.FormError
            s = wire[current : current + l].unwrap()
            current += l
            rdlen -= l
            strings.append(s)
        (replacement, cused) = dns.name.from_wire(wire[: current + rdlen],
                                                  current)
        if cused != rdlen:
            raise dns.exception.FormError
        if not origin is None:
            replacement = replacement.relativize(origin)
        return cls(rdclass, rdtype, order, preference, strings[0], strings[1],
                   strings[2], replacement)

    from_wire = classmethod(from_wire)

    def choose_relativity(self, origin = None, relativize = True):
        self.replacement = self.replacement.choose_relativity(origin,
                                                              relativize)

    def _cmp(self, other):
        sp = struct.pack("!HH", self.order, self.preference)
        op = struct.pack("!HH", other.order, other.preference)
        v = cmp(sp, op)
        if v == 0:
            v = cmp(self.flags, other.flags)
            if v == 0:
                v = cmp(self.service, other.service)
                if v == 0:
                    v = cmp(self.regexp, other.regexp)
                    if v == 0:
                        v = cmp(self.replacement, other.replacement)
        return v
