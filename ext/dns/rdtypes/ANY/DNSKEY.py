# Copyright (C) 2004-2007, 2009-2011 Nominum, Inc.
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
import dns.dnssec
import dns.rdata

# flag constants
SEP = 0x0001
REVOKE = 0x0080
ZONE = 0x0100

class DNSKEY(dns.rdata.Rdata):
    """DNSKEY record

    @ivar flags: the key flags
    @type flags: int
    @ivar protocol: the protocol for which this key may be used
    @type protocol: int
    @ivar algorithm: the algorithm used for the key
    @type algorithm: int
    @ivar key: the public key
    @type key: string"""

    __slots__ = ['flags', 'protocol', 'algorithm', 'key']

    def __init__(self, rdclass, rdtype, flags, protocol, algorithm, key):
        super(DNSKEY, self).__init__(rdclass, rdtype)
        self.flags = flags
        self.protocol = protocol
        self.algorithm = algorithm
        self.key = key

    def to_text(self, origin=None, relativize=True, **kw):
        return '%d %d %d %s' % (self.flags, self.protocol, self.algorithm,
                                dns.rdata._base64ify(self.key))

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        flags = tok.get_uint16()
        protocol = tok.get_uint8()
        algorithm = dns.dnssec.algorithm_from_text(tok.get_string())
        chunks = []
        while 1:
            t = tok.get().unescape()
            if t.is_eol_or_eof():
                break
            if not t.is_identifier():
                raise dns.exception.SyntaxError
            chunks.append(t.value)
        b64 = ''.join(chunks)
        key = b64.decode('base64_codec')
        return cls(rdclass, rdtype, flags, protocol, algorithm, key)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        header = struct.pack("!HBB", self.flags, self.protocol, self.algorithm)
        file.write(header)
        file.write(self.key)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        if rdlen < 4:
            raise dns.exception.FormError
        header = struct.unpack('!HBB', wire[current : current + 4])
        current += 4
        rdlen -= 4
        key = wire[current : current + rdlen].unwrap()
        return cls(rdclass, rdtype, header[0], header[1], header[2],
                   key)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        hs = struct.pack("!HBB", self.flags, self.protocol, self.algorithm)
        ho = struct.pack("!HBB", other.flags, other.protocol, other.algorithm)
        v = cmp(hs, ho)
        if v == 0:
            v = cmp(self.key, other.key)
        return v
