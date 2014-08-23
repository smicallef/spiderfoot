# Copyright (C) 2005-2007, 2009-2011 Nominum, Inc.
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

import dns.rdata
import dns.rdatatype

class TLSA(dns.rdata.Rdata):
    """TLSA record

    @ivar usage: The certificate usage
    @type usage: int
    @ivar selector: The selector field
    @type selector: int
    @ivar mtype: The 'matching type' field
    @type mtype: int
    @ivar cert: The 'Certificate Association Data' field
    @type cert: string
    @see: RFC 6698"""

    __slots__ = ['usage', 'selector', 'mtype', 'cert']

    def __init__(self, rdclass, rdtype, usage, selector,
                 mtype, cert):
        super(TLSA, self).__init__(rdclass, rdtype)
        self.usage = usage
        self.selector = selector
        self.mtype = mtype
        self.cert = cert

    def to_text(self, origin=None, relativize=True, **kw):
        return '%d %d %d %s' % (self.usage,
                                self.selector,
                                self.mtype,
                                dns.rdata._hexify(self.cert,
                                               chunksize=128))

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        usage = tok.get_uint8()
        selector = tok.get_uint8()
        mtype = tok.get_uint8()
        cert_chunks = []
        while 1:
            t = tok.get().unescape()
            if t.is_eol_or_eof():
                break
            if not t.is_identifier():
                raise dns.exception.SyntaxError
            cert_chunks.append(t.value)
        cert = ''.join(cert_chunks)
        cert = cert.decode('hex_codec')
        return cls(rdclass, rdtype, usage, selector, mtype, cert)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        header = struct.pack("!BBB", self.usage, self.selector, self.mtype)
        file.write(header)
        file.write(self.cert)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        header = struct.unpack("!BBB", wire[current : current + 3])
        current += 3
        rdlen -= 3
        cert = wire[current : current + rdlen].unwrap()
        return cls(rdclass, rdtype, header[0], header[1], header[2], cert)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        hs = struct.pack("!BBB", self.usage, self.selector, self.mtype)
        ho = struct.pack("!BBB", other.usage, other.selector, other.mtype)
        v = cmp(hs, ho)
        if v == 0:
            v = cmp(self.cert, other.cert)
        return v
