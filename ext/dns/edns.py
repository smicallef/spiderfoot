# Copyright (C) 2009, 2011 Nominum, Inc.
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

"""EDNS Options"""

NSID = 3

class Option(object):
    """Base class for all EDNS option types.
    """

    def __init__(self, otype):
        """Initialize an option.
        @param otype: The rdata type
        @type otype: int
        """
        self.otype = otype

    def to_wire(self, file):
        """Convert an option to wire format.
        """
        raise NotImplementedError

    def from_wire(cls, otype, wire, current, olen):
        """Build an EDNS option object from wire format

        @param otype: The option type
        @type otype: int
        @param wire: The wire-format message
        @type wire: string
        @param current: The offet in wire of the beginning of the rdata.
        @type current: int
        @param olen: The length of the wire-format option data
        @type olen: int
        @rtype: dns.edns.Option instance"""
        raise NotImplementedError

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        """Compare an EDNS option with another option of the same type.
        Return < 0 if self < other, 0 if self == other, and > 0 if self > other.
        """
        raise NotImplementedError

    def __eq__(self, other):
        if not isinstance(other, Option):
            return False
        if self.otype != other.otype:
            return False
        return self._cmp(other) == 0

    def __ne__(self, other):
        if not isinstance(other, Option):
            return False
        if self.otype != other.otype:
            return False
        return self._cmp(other) != 0

    def __lt__(self, other):
        if not isinstance(other, Option) or \
               self.otype != other.otype:
            return NotImplemented
        return self._cmp(other) < 0

    def __le__(self, other):
        if not isinstance(other, Option) or \
               self.otype != other.otype:
            return NotImplemented
        return self._cmp(other) <= 0

    def __ge__(self, other):
        if not isinstance(other, Option) or \
               self.otype != other.otype:
            return NotImplemented
        return self._cmp(other) >= 0

    def __gt__(self, other):
        if not isinstance(other, Option) or \
               self.otype != other.otype:
            return NotImplemented
        return self._cmp(other) > 0


class GenericOption(Option):
    """Generate Rdata Class

    This class is used for EDNS option types for which we have no better
    implementation.
    """

    def __init__(self, otype, data):
        super(GenericOption, self).__init__(otype)
        self.data = data

    def to_wire(self, file):
        file.write(self.data)

    def from_wire(cls, otype, wire, current, olen):
        return cls(otype, wire[current : current + olen])

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
	return cmp(self.data, other.data)

_type_to_class = {
}

def get_option_class(otype):
    cls = _type_to_class.get(otype)
    if cls is None:
        cls = GenericOption
    return cls

def option_from_wire(otype, wire, current, olen):
    """Build an EDNS option object from wire format

    @param otype: The option type
    @type otype: int
    @param wire: The wire-format message
    @type wire: string
    @param current: The offet in wire of the beginning of the rdata.
    @type current: int
    @param olen: The length of the wire-format option data
    @type olen: int
    @rtype: dns.edns.Option instance"""

    cls = get_option_class(otype)
    return cls.from_wire(otype, wire, current, olen)
