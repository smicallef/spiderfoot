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

"""DNS TTL conversion."""

import dns.exception

class BadTTL(dns.exception.SyntaxError):
    pass

def from_text(text):
    """Convert the text form of a TTL to an integer.

    The BIND 8 units syntax for TTLs (e.g. '1w6d4h3m10s') is supported.

    @param text: the textual TTL
    @type text: string
    @raises dns.ttl.BadTTL: the TTL is not well-formed
    @rtype: int
    """

    if text.isdigit():
        total = long(text)
    else:
        if not text[0].isdigit():
            raise BadTTL
        total = 0L
        current = 0L
        for c in text:
            if c.isdigit():
                current *= 10
                current += long(c)
            else:
                c = c.lower()
                if c == 'w':
                    total += current * 604800L
                elif c == 'd':
                    total += current * 86400L
                elif c == 'h':
                    total += current * 3600L
                elif c == 'm':
                    total += current * 60L
                elif c == 's':
                    total += current
                else:
                    raise BadTTL("unknown unit '%s'" % c)
                current = 0
        if not current == 0:
            raise BadTTL("trailing integer")
    if total < 0L or total > 2147483647L:
        raise BadTTL("TTL should be between 0 and 2^31 - 1 (inclusive)")
    return total
