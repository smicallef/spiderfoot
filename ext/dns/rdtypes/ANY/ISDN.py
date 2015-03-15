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

import dns.exception
import dns.rdata
import dns.tokenizer

class ISDN(dns.rdata.Rdata):
    """ISDN record

    @ivar address: the ISDN address
    @type address: string
    @ivar subaddress: the ISDN subaddress (or '' if not present)
    @type subaddress: string
    @see: RFC 1183"""

    __slots__ = ['address', 'subaddress']

    def __init__(self, rdclass, rdtype, address, subaddress):
        super(ISDN, self).__init__(rdclass, rdtype)
        self.address = address
        self.subaddress = subaddress

    def to_text(self, origin=None, relativize=True, **kw):
        if self.subaddress:
            return '"%s" "%s"' % (dns.rdata._escapify(self.address),
                                  dns.rdata._escapify(self.subaddress))
        else:
            return '"%s"' % dns.rdata._escapify(self.address)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        address = tok.get_string()
        t = tok.get()
        if not t.is_eol_or_eof():
            tok.unget(t)
            subaddress = tok.get_string()
        else:
            tok.unget(t)
            subaddress = ''
        tok.get_eol()
        return cls(rdclass, rdtype, address, subaddress)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        l = len(self.address)
        assert l < 256
        byte = chr(l)
        file.write(byte)
        file.write(self.address)
        l = len(self.subaddress)
        if l > 0:
            assert l < 256
            byte = chr(l)
            file.write(byte)
            file.write(self.subaddress)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        l = ord(wire[current])
        current += 1
        rdlen -= 1
        if l > rdlen:
            raise dns.exception.FormError
        address = wire[current : current + l].unwrap()
        current += l
        rdlen -= l
        if rdlen > 0:
            l = ord(wire[current])
            current += 1
            rdlen -= 1
            if l != rdlen:
                raise dns.exception.FormError
            subaddress = wire[current : current + l].unwrap()
        else:
            subaddress = ''
        return cls(rdclass, rdtype, address, subaddress)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        v = cmp(self.address, other.address)
        if v == 0:
            v = cmp(self.subaddress, other.subaddress)
        return v
