# Copyright (C) 2001-2007, 2009-2011 Nominum, Inc.
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

"""DNS Result Codes."""

import dns.exception

NOERROR = 0
FORMERR = 1
SERVFAIL = 2
NXDOMAIN = 3
NOTIMP = 4
REFUSED = 5
YXDOMAIN = 6
YXRRSET = 7
NXRRSET = 8
NOTAUTH = 9
NOTZONE = 10
BADVERS = 16

_by_text = {
    'NOERROR' : NOERROR,
    'FORMERR' : FORMERR,
    'SERVFAIL' : SERVFAIL,
    'NXDOMAIN' : NXDOMAIN,
    'NOTIMP' : NOTIMP,
    'REFUSED' : REFUSED,
    'YXDOMAIN' : YXDOMAIN,
    'YXRRSET' : YXRRSET,
    'NXRRSET' : NXRRSET,
    'NOTAUTH' : NOTAUTH,
    'NOTZONE' : NOTZONE,
    'BADVERS' : BADVERS
}

# We construct the inverse mapping programmatically to ensure that we
# cannot make any mistakes (e.g. omissions, cut-and-paste errors) that
# would cause the mapping not to be a true inverse.

_by_value = dict([(y, x) for x, y in _by_text.iteritems()])


class UnknownRcode(dns.exception.DNSException):
    """Raised if an rcode is unknown."""
    pass

def from_text(text):
    """Convert text into an rcode.

    @param text: the texual rcode
    @type text: string
    @raises UnknownRcode: the rcode is unknown
    @rtype: int
    """

    if text.isdigit():
        v = int(text)
        if v >= 0 and v <= 4095:
            return v
    v = _by_text.get(text.upper())
    if v is None:
        raise UnknownRcode
    return v

def from_flags(flags, ednsflags):
    """Return the rcode value encoded by flags and ednsflags.

    @param flags: the DNS flags
    @type flags: int
    @param ednsflags: the EDNS flags
    @type ednsflags: int
    @raises ValueError: rcode is < 0 or > 4095
    @rtype: int
    """

    value = (flags & 0x000f) | ((ednsflags >> 20) & 0xff0)
    if value < 0 or value > 4095:
        raise ValueError('rcode must be >= 0 and <= 4095')
    return value

def to_flags(value):
    """Return a (flags, ednsflags) tuple which encodes the rcode.

    @param value: the rcode
    @type value: int
    @raises ValueError: rcode is < 0 or > 4095
    @rtype: (int, int) tuple
    """

    if value < 0 or value > 4095:
        raise ValueError('rcode must be >= 0 and <= 4095')
    v = value & 0xf
    ev = long(value & 0xff0) << 20
    return (v, ev)

def to_text(value):
    """Convert rcode into text.

    @param value: the rcode
    @type value: int
    @rtype: string
    """

    text = _by_value.get(value)
    if text is None:
        text = str(value)
    return text
