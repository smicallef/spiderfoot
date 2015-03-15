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

"""IPv4 helper functions."""

import struct

import dns.exception

def inet_ntoa(address):
    """Convert an IPv4 address in network form to text form.

    @param address: The IPv4 address
    @type address: string
    @returns: string
    """
    if len(address) != 4:
        raise dns.exception.SyntaxError
    return '%u.%u.%u.%u' % (ord(address[0]), ord(address[1]),
                            ord(address[2]), ord(address[3]))

def inet_aton(text):
    """Convert an IPv4 address in text form to network form.

    @param text: The IPv4 address
    @type text: string
    @returns: string
    """
    parts = text.split('.')
    if len(parts) != 4:
        raise dns.exception.SyntaxError
    for part in parts:
        if not part.isdigit():
            raise dns.exception.SyntaxError
        if len(part) > 1 and part[0] == '0':
            # No leading zeros
            raise dns.exception.SyntaxError
    try:
        bytes = [int(part) for part in parts]
        return struct.pack('BBBB', *bytes)
    except:
        raise dns.exception.SyntaxError
