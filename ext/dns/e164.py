# Copyright (C) 2006, 2007, 2009, 2011 Nominum, Inc.
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

"""DNS E.164 helpers

@var public_enum_domain: The DNS public ENUM domain, e164.arpa.
@type public_enum_domain: dns.name.Name object
"""

import dns.exception
import dns.name
import dns.resolver

public_enum_domain = dns.name.from_text('e164.arpa.')

def from_e164(text, origin=public_enum_domain):
    """Convert an E.164 number in textual form into a Name object whose
    value is the ENUM domain name for that number.
    @param text: an E.164 number in textual form.
    @type text: str
    @param origin: The domain in which the number should be constructed.
    The default is e164.arpa.
    @type origin: dns.name.Name object or None
    @rtype: dns.name.Name object
    """
    parts = [d for d in text if d.isdigit()]
    parts.reverse()
    return dns.name.from_text('.'.join(parts), origin=origin)

def to_e164(name, origin=public_enum_domain, want_plus_prefix=True):
    """Convert an ENUM domain name into an E.164 number.
    @param name: the ENUM domain name.
    @type name: dns.name.Name object.
    @param origin: A domain containing the ENUM domain name.  The
    name is relativized to this domain before being converted to text.
    @type origin: dns.name.Name object or None
    @param want_plus_prefix: if True, add a '+' to the beginning of the
    returned number.
    @rtype: str
    """
    if not origin is None:
        name = name.relativize(origin)
    dlabels = [d for d in name.labels if (d.isdigit() and len(d) == 1)]
    if len(dlabels) != len(name.labels):
        raise dns.exception.SyntaxError('non-digit labels in ENUM domain name')
    dlabels.reverse()
    text = ''.join(dlabels)
    if want_plus_prefix:
        text = '+' + text
    return text

def query(number, domains, resolver=None):
    """Look for NAPTR RRs for the specified number in the specified domains.

    e.g. lookup('16505551212', ['e164.dnspython.org.', 'e164.arpa.'])
    """
    if resolver is None:
        resolver = dns.resolver.get_default_resolver()
    for domain in domains:
        if isinstance(domain, (str, unicode)):
            domain = dns.name.from_text(domain)
        qname = dns.e164.from_e164(number, domain)
        try:
            return resolver.query(qname, 'NAPTR')
        except dns.resolver.NXDOMAIN:
            pass
    raise dns.resolver.NXDOMAIN
