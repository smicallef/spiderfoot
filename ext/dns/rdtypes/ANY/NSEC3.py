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

import base64
import cStringIO
import string
import struct

import dns.exception
import dns.rdata
import dns.rdatatype

b32_hex_to_normal = string.maketrans('0123456789ABCDEFGHIJKLMNOPQRSTUV',
                                     'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')
b32_normal_to_hex = string.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                     '0123456789ABCDEFGHIJKLMNOPQRSTUV')

# hash algorithm constants
SHA1 = 1

# flag constants
OPTOUT = 1

class NSEC3(dns.rdata.Rdata):
    """NSEC3 record

    @ivar algorithm: the hash algorithm number
    @type algorithm: int
    @ivar flags: the flags
    @type flags: int
    @ivar iterations: the number of iterations
    @type iterations: int
    @ivar salt: the salt
    @type salt: string
    @ivar next: the next name hash
    @type next: string
    @ivar windows: the windowed bitmap list
    @type windows: list of (window number, string) tuples"""

    __slots__ = ['algorithm', 'flags', 'iterations', 'salt', 'next', 'windows']

    def __init__(self, rdclass, rdtype, algorithm, flags, iterations, salt,
                 next, windows):
        super(NSEC3, self).__init__(rdclass, rdtype)
        self.algorithm = algorithm
        self.flags = flags
        self.iterations = iterations
        self.salt = salt
        self.next = next
        self.windows = windows

    def to_text(self, origin=None, relativize=True, **kw):
        next = base64.b32encode(self.next).translate(b32_normal_to_hex).lower()
        if self.salt == '':
            salt = '-'
        else:
            salt = self.salt.encode('hex-codec')
        text = ''
        for (window, bitmap) in self.windows:
            bits = []
            for i in xrange(0, len(bitmap)):
                byte = ord(bitmap[i])
                for j in xrange(0, 8):
                    if byte & (0x80 >> j):
                        bits.append(dns.rdatatype.to_text(window * 256 + \
                                                          i * 8 + j))
            text += (' ' + ' '.join(bits))
        return '%u %u %u %s %s%s' % (self.algorithm, self.flags, self.iterations,
                                     salt, next, text)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        algorithm = tok.get_uint8()
        flags = tok.get_uint8()
        iterations = tok.get_uint16()
        salt = tok.get_string()
        if salt == '-':
            salt = ''
        else:
            salt = salt.decode('hex-codec')
        next = tok.get_string().upper().translate(b32_hex_to_normal)
        next = base64.b32decode(next)
        rdtypes = []
        while 1:
            token = tok.get().unescape()
            if token.is_eol_or_eof():
                break
            nrdtype = dns.rdatatype.from_text(token.value)
            if nrdtype == 0:
                raise dns.exception.SyntaxError("NSEC3 with bit 0")
            if nrdtype > 65535:
                raise dns.exception.SyntaxError("NSEC3 with bit > 65535")
            rdtypes.append(nrdtype)
        rdtypes.sort()
        window = 0
        octets = 0
        prior_rdtype = 0
        bitmap = ['\0'] * 32
        windows = []
        for nrdtype in rdtypes:
            if nrdtype == prior_rdtype:
                continue
            prior_rdtype = nrdtype
            new_window = nrdtype // 256
            if new_window != window:
                if octets != 0:
                    windows.append((window, ''.join(bitmap[0:octets])))
                bitmap = ['\0'] * 32
                window = new_window
            offset = nrdtype % 256
            byte = offset // 8
            bit = offset % 8
            octets = byte + 1
            bitmap[byte] = chr(ord(bitmap[byte]) | (0x80 >> bit))
        if octets != 0:
            windows.append((window, ''.join(bitmap[0:octets])))
        return cls(rdclass, rdtype, algorithm, flags, iterations, salt, next, windows)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        l = len(self.salt)
        file.write(struct.pack("!BBHB", self.algorithm, self.flags,
                               self.iterations, l))
        file.write(self.salt)
        l = len(self.next)
        file.write(struct.pack("!B", l))
        file.write(self.next)
        for (window, bitmap) in self.windows:
            file.write(chr(window))
            file.write(chr(len(bitmap)))
            file.write(bitmap)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        (algorithm, flags, iterations, slen) = struct.unpack('!BBHB',
                                                             wire[current : current + 5])
        current += 5
        rdlen -= 5
        salt = wire[current : current + slen].unwrap()
        current += slen
        rdlen -= slen
        (nlen, ) = struct.unpack('!B', wire[current])
        current += 1
        rdlen -= 1
        next = wire[current : current + nlen].unwrap()
        current += nlen
        rdlen -= nlen
        windows = []
        while rdlen > 0:
            if rdlen < 3:
                raise dns.exception.FormError("NSEC3 too short")
            window = ord(wire[current])
            octets = ord(wire[current + 1])
            if octets == 0 or octets > 32:
                raise dns.exception.FormError("bad NSEC3 octets")
            current += 2
            rdlen -= 2
            if rdlen < octets:
                raise dns.exception.FormError("bad NSEC3 bitmap length")
            bitmap = wire[current : current + octets].unwrap()
            current += octets
            rdlen -= octets
            windows.append((window, bitmap))
        return cls(rdclass, rdtype, algorithm, flags, iterations, salt, next, windows)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        b1 = cStringIO.StringIO()
        self.to_wire(b1)
        b2 = cStringIO.StringIO()
        other.to_wire(b2)
        return cmp(b1.getvalue(), b2.getvalue())
