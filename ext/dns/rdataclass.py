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

"""DNS Rdata Classes.

@var _by_text: The rdata class textual name to value mapping
@type _by_text: dict
@var _by_value: The rdata class value to textual name mapping
@type _by_value: dict
@var _metaclasses: If an rdataclass is a metaclass, there will be a mapping
whose key is the rdatatype value and whose value is True in this dictionary.
@type _metaclasses: dict"""

import re

import dns.exception

RESERVED0 = 0
IN = 1
CH = 3
HS = 4
NONE = 254
ANY = 255

_by_text = {
    'RESERVED0' : RESERVED0,
    'IN' : IN,
    'CH' : CH,
    'HS' : HS,
    'NONE' : NONE,
    'ANY' : ANY
    }

# We construct the inverse mapping programmatically to ensure that we
# cannot make any mistakes (e.g. omissions, cut-and-paste errors) that
# would cause the mapping not to be true inverse.

_by_value = dict([(y, x) for x, y in _by_text.iteritems()])

# Now that we've built the inverse map, we can add class aliases to
# the _by_text mapping.

_by_text.update({
    'INTERNET' : IN,
    'CHAOS' : CH,
    'HESIOD' : HS
    })

_metaclasses = {
    NONE : True,
    ANY : True
    }

_unknown_class_pattern = re.compile('CLASS([0-9]+)$', re.I);

class UnknownRdataclass(dns.exception.DNSException):
    """Raised when a class is unknown."""
    pass

def from_text(text):
    """Convert text into a DNS rdata class value.
    @param text: the text
    @type text: string
    @rtype: int
    @raises dns.rdataclass.UnknownRdataclass: the class is unknown
    @raises ValueError: the rdata class value is not >= 0 and <= 65535
    """

    value = _by_text.get(text.upper())
    if value is None:
        match = _unknown_class_pattern.match(text)
        if match == None:
            raise UnknownRdataclass
        value = int(match.group(1))
        if value < 0 or value > 65535:
            raise ValueError("class must be between >= 0 and <= 65535")
    return value

def to_text(value):
    """Convert a DNS rdata class to text.
    @param value: the rdata class value
    @type value: int
    @rtype: string
    @raises ValueError: the rdata class value is not >= 0 and <= 65535
    """

    if value < 0 or value > 65535:
        raise ValueError("class must be between >= 0 and <= 65535")
    text = _by_value.get(value)
    if text is None:
        text = 'CLASS' + `value`
    return text

def is_metaclass(rdclass):
    """True if the class is a metaclass.
    @param rdclass: the rdata class
    @type rdclass: int
    @rtype: bool"""

    if _metaclasses.has_key(rdclass):
        return True
    return False
