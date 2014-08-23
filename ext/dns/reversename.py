# Copyright (C) 2006, 2007, 2009-2011 Nominum, Inc.
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

"""DNS Reverse Map Names.

@var ipv4_reverse_domain: The DNS IPv4 reverse-map domain, in-addr.arpa.
@type ipv4_reverse_domain: dns.name.Name object
@var ipv6_reverse_domain: The DNS IPv6 reverse-map domain, ip6.arpa.
@type ipv6_reverse_domain: dns.name.Name object
"""

import dns.name
import dns.ipv6
import dns.ipv4

ipv4_reverse_domain = dns.name.from_text('in-addr.arpa.')
ipv6_reverse_domain = dns.name.from_text('ip6.arpa.')

def from_address(text):
    """Convert an IPv4 or IPv6 address in textual form into a Name object whose
    value is the reverse-map domain name of the address.
    @param text: an IPv4 or IPv6 address in textual form (e.g. '127.0.0.1',
    '::1')
    @type text: str
    @rtype: dns.name.Name object
    """
    try:
        parts = list(dns.ipv6.inet_aton(text).encode('hex_codec'))
        origin = ipv6_reverse_domain
    except:
        parts = ['%d' % ord(byte) for byte in dns.ipv4.inet_aton(text)]
        origin = ipv4_reverse_domain
    parts.reverse()
    return dns.name.from_text('.'.join(parts), origin=origin)

def to_address(name):
    """Convert a reverse map domain name into textual address form.
    @param name: an IPv4 or IPv6 address in reverse-map form.
    @type name: dns.name.Name object
    @rtype: str
    """
    if name.is_subdomain(ipv4_reverse_domain):
        name = name.relativize(ipv4_reverse_domain)
        labels = list(name.labels)
        labels.reverse()
        text = '.'.join(labels)
        # run through inet_aton() to check syntax and make pretty.
        return dns.ipv4.inet_ntoa(dns.ipv4.inet_aton(text))
    elif name.is_subdomain(ipv6_reverse_domain):
        name = name.relativize(ipv6_reverse_domain)
        labels = list(name.labels)
        labels.reverse()
        parts = []
        i = 0
        l = len(labels)
        while i < l:
            parts.append(''.join(labels[i:i+4]))
            i += 4
        text = ':'.join(parts)
        # run through inet_aton() to check syntax and make pretty.
        return dns.ipv6.inet_ntoa(dns.ipv6.inet_aton(text))
    else:
        raise dns.exception.SyntaxError('unknown reverse-map address family')
