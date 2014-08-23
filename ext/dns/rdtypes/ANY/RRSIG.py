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

import calendar
import struct
import time

import dns.dnssec
import dns.exception
import dns.rdata
import dns.rdatatype

class BadSigTime(dns.exception.DNSException):
    """Raised when a SIG or RRSIG RR's time cannot be parsed."""
    pass

def sigtime_to_posixtime(what):
    if len(what) != 14:
        raise BadSigTime
    year = int(what[0:4])
    month = int(what[4:6])
    day = int(what[6:8])
    hour = int(what[8:10])
    minute = int(what[10:12])
    second = int(what[12:14])
    return calendar.timegm((year, month, day, hour, minute, second,
                            0, 0, 0))

def posixtime_to_sigtime(what):
    return time.strftime('%Y%m%d%H%M%S', time.gmtime(what))

class RRSIG(dns.rdata.Rdata):
    """RRSIG record

    @ivar type_covered: the rdata type this signature covers
    @type type_covered: int
    @ivar algorithm: the algorithm used for the sig
    @type algorithm: int
    @ivar labels: number of labels
    @type labels: int
    @ivar original_ttl: the original TTL
    @type original_ttl: long
    @ivar expiration: signature expiration time
    @type expiration: long
    @ivar inception: signature inception time
    @type inception: long
    @ivar key_tag: the key tag
    @type key_tag: int
    @ivar signer: the signer
    @type signer: dns.name.Name object
    @ivar signature: the signature
    @type signature: string"""

    __slots__ = ['type_covered', 'algorithm', 'labels', 'original_ttl',
                 'expiration', 'inception', 'key_tag', 'signer',
                 'signature']

    def __init__(self, rdclass, rdtype, type_covered, algorithm, labels,
                 original_ttl, expiration, inception, key_tag, signer,
                 signature):
        super(RRSIG, self).__init__(rdclass, rdtype)
        self.type_covered = type_covered
        self.algorithm = algorithm
        self.labels = labels
        self.original_ttl = original_ttl
        self.expiration = expiration
        self.inception = inception
        self.key_tag = key_tag
        self.signer = signer
        self.signature = signature

    def covers(self):
        return self.type_covered

    def to_text(self, origin=None, relativize=True, **kw):
        return '%s %d %d %d %s %s %d %s %s' % (
            dns.rdatatype.to_text(self.type_covered),
            self.algorithm,
            self.labels,
            self.original_ttl,
            posixtime_to_sigtime(self.expiration),
            posixtime_to_sigtime(self.inception),
            self.key_tag,
            self.signer,
            dns.rdata._base64ify(self.signature)
            )

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        type_covered = dns.rdatatype.from_text(tok.get_string())
        algorithm = dns.dnssec.algorithm_from_text(tok.get_string())
        labels = tok.get_int()
        original_ttl = tok.get_ttl()
        expiration = sigtime_to_posixtime(tok.get_string())
        inception = sigtime_to_posixtime(tok.get_string())
        key_tag = tok.get_int()
        signer = tok.get_name()
        signer = signer.choose_relativity(origin, relativize)
        chunks = []
        while 1:
            t = tok.get().unescape()
            if t.is_eol_or_eof():
                break
            if not t.is_identifier():
                raise dns.exception.SyntaxError
            chunks.append(t.value)
        b64 = ''.join(chunks)
        signature = b64.decode('base64_codec')
        return cls(rdclass, rdtype, type_covered, algorithm, labels,
                   original_ttl, expiration, inception, key_tag, signer,
                   signature)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        header = struct.pack('!HBBIIIH', self.type_covered,
                             self.algorithm, self.labels,
                             self.original_ttl, self.expiration,
                             self.inception, self.key_tag)
        file.write(header)
        self.signer.to_wire(file, None, origin)
        file.write(self.signature)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        header = struct.unpack('!HBBIIIH', wire[current : current + 18])
        current += 18
        rdlen -= 18
        (signer, cused) = dns.name.from_wire(wire[: current + rdlen], current)
        current += cused
        rdlen -= cused
        if not origin is None:
            signer = signer.relativize(origin)
        signature = wire[current : current + rdlen].unwrap()
        return cls(rdclass, rdtype, header[0], header[1], header[2],
                   header[3], header[4], header[5], header[6], signer,
                   signature)

    from_wire = classmethod(from_wire)

    def choose_relativity(self, origin = None, relativize = True):
        self.signer = self.signer.choose_relativity(origin, relativize)

    def _cmp(self, other):
        return self._wire_cmp(other)
