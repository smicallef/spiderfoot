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

"""DNS rdata.

@var _rdata_modules: A dictionary mapping a (rdclass, rdtype) tuple to
the module which implements that type.
@type _rdata_modules: dict
@var _module_prefix: The prefix to use when forming modules names.  The
default is 'dns.rdtypes'.  Changing this value will break the library.
@type _module_prefix: string
@var _hex_chunk: At most this many octets that will be represented in each
chunk of hexstring that _hexify() produces before whitespace occurs.
@type _hex_chunk: int"""

import cStringIO

import dns.exception
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.tokenizer
import dns.wiredata

_hex_chunksize = 32

def _hexify(data, chunksize=None):
    """Convert a binary string into its hex encoding, broken up into chunks
    of I{chunksize} characters separated by a space.

    @param data: the binary string
    @type data: string
    @param chunksize: the chunk size.  Default is L{dns.rdata._hex_chunksize}
    @rtype: string
    """

    if chunksize is None:
        chunksize = _hex_chunksize
    hex = data.encode('hex_codec')
    l = len(hex)
    if l > chunksize:
        chunks = []
        i = 0
        while i < l:
            chunks.append(hex[i : i + chunksize])
            i += chunksize
        hex = ' '.join(chunks)
    return hex

_base64_chunksize = 32

def _base64ify(data, chunksize=None):
    """Convert a binary string into its base64 encoding, broken up into chunks
    of I{chunksize} characters separated by a space.

    @param data: the binary string
    @type data: string
    @param chunksize: the chunk size.  Default is
    L{dns.rdata._base64_chunksize}
    @rtype: string
    """

    if chunksize is None:
        chunksize = _base64_chunksize
    b64 = data.encode('base64_codec')
    b64 = b64.replace('\n', '')
    l = len(b64)
    if l > chunksize:
        chunks = []
        i = 0
        while i < l:
            chunks.append(b64[i : i + chunksize])
            i += chunksize
        b64 = ' '.join(chunks)
    return b64

__escaped = {
    '"' : True,
    '\\' : True,
    }

def _escapify(qstring):
    """Escape the characters in a quoted string which need it.

    @param qstring: the string
    @type qstring: string
    @returns: the escaped string
    @rtype: string
    """

    text = ''
    for c in qstring:
        if c in __escaped:
            text += '\\' + c
        elif ord(c) >= 0x20 and ord(c) < 0x7F:
            text += c
        else:
            text += '\\%03d' % ord(c)
    return text

def _truncate_bitmap(what):
    """Determine the index of greatest byte that isn't all zeros, and
    return the bitmap that contains all the bytes less than that index.

    @param what: a string of octets representing a bitmap.
    @type what: string
    @rtype: string
    """

    for i in xrange(len(what) - 1, -1, -1):
        if what[i] != '\x00':
            break
    return ''.join(what[0 : i + 1])

class Rdata(object):
    """Base class for all DNS rdata types.
    """

    __slots__ = ['rdclass', 'rdtype']

    def __init__(self, rdclass, rdtype):
        """Initialize an rdata.
        @param rdclass: The rdata class
        @type rdclass: int
        @param rdtype: The rdata type
        @type rdtype: int
        """

        self.rdclass = rdclass
        self.rdtype = rdtype

    def covers(self):
        """DNS SIG/RRSIG rdatas apply to a specific type; this type is
        returned by the covers() function.  If the rdata type is not
        SIG or RRSIG, dns.rdatatype.NONE is returned.  This is useful when
        creating rdatasets, allowing the rdataset to contain only RRSIGs
        of a particular type, e.g. RRSIG(NS).
        @rtype: int
        """

        return dns.rdatatype.NONE

    def extended_rdatatype(self):
        """Return a 32-bit type value, the least significant 16 bits of
        which are the ordinary DNS type, and the upper 16 bits of which are
        the "covered" type, if any.
        @rtype: int
        """

        return self.covers() << 16 | self.rdtype

    def to_text(self, origin=None, relativize=True, **kw):
        """Convert an rdata to text format.
        @rtype: string
        """
        raise NotImplementedError

    def to_wire(self, file, compress = None, origin = None):
        """Convert an rdata to wire format.
        @rtype: string
        """

        raise NotImplementedError

    def to_digestable(self, origin = None):
        """Convert rdata to a format suitable for digesting in hashes.  This
        is also the DNSSEC canonical form."""
        f = cStringIO.StringIO()
        self.to_wire(f, None, origin)
        return f.getvalue()

    def validate(self):
        """Check that the current contents of the rdata's fields are
        valid.  If you change an rdata by assigning to its fields,
        it is a good idea to call validate() when you are done making
        changes.
        """
        dns.rdata.from_text(self.rdclass, self.rdtype, self.to_text())

    def __repr__(self):
        covers = self.covers()
        if covers == dns.rdatatype.NONE:
            ctext = ''
        else:
            ctext = '(' + dns.rdatatype.to_text(covers) + ')'
        return '<DNS ' + dns.rdataclass.to_text(self.rdclass) + ' ' + \
               dns.rdatatype.to_text(self.rdtype) + ctext + ' rdata: ' + \
               str(self) + '>'

    def __str__(self):
        return self.to_text()

    def _cmp(self, other):
        """Compare an rdata with another rdata of the same rdtype and
        rdclass.  Return < 0 if self < other in the DNSSEC ordering,
        0 if self == other, and > 0 if self > other.
        """

        raise NotImplementedError

    def __eq__(self, other):
        if not isinstance(other, Rdata):
            return False
        if self.rdclass != other.rdclass or \
           self.rdtype != other.rdtype:
            return False
        return self._cmp(other) == 0

    def __ne__(self, other):
        if not isinstance(other, Rdata):
            return True
        if self.rdclass != other.rdclass or \
           self.rdtype != other.rdtype:
            return True
        return self._cmp(other) != 0

    def __lt__(self, other):
        if not isinstance(other, Rdata) or \
               self.rdclass != other.rdclass or \
               self.rdtype != other.rdtype:
            return NotImplemented
        return self._cmp(other) < 0

    def __le__(self, other):
        if not isinstance(other, Rdata) or \
               self.rdclass != other.rdclass or \
               self.rdtype != other.rdtype:
            return NotImplemented
        return self._cmp(other) <= 0

    def __ge__(self, other):
        if not isinstance(other, Rdata) or \
               self.rdclass != other.rdclass or \
               self.rdtype != other.rdtype:
            return NotImplemented
        return self._cmp(other) >= 0

    def __gt__(self, other):
        if not isinstance(other, Rdata) or \
               self.rdclass != other.rdclass or \
               self.rdtype != other.rdtype:
            return NotImplemented
        return self._cmp(other) > 0

    def __hash__(self):
        return hash(self.to_digestable(dns.name.root))

    def _wire_cmp(self, other):
        # A number of types compare rdata in wire form, so we provide
        # the method here instead of duplicating it.
        #
        # We specifiy an arbitrary origin of '.' when doing the
        # comparison, since the rdata may have relative names and we
        # can't convert a relative name to wire without an origin.
        b1 = cStringIO.StringIO()
        self.to_wire(b1, None, dns.name.root)
        b2 = cStringIO.StringIO()
        other.to_wire(b2, None, dns.name.root)
        return cmp(b1.getvalue(), b2.getvalue())

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        """Build an rdata object from text format.

        @param rdclass: The rdata class
        @type rdclass: int
        @param rdtype: The rdata type
        @type rdtype: int
        @param tok: The tokenizer
        @type tok: dns.tokenizer.Tokenizer
        @param origin: The origin to use for relative names
        @type origin: dns.name.Name
        @param relativize: should names be relativized?
        @type relativize: bool
        @rtype: dns.rdata.Rdata instance
        """

        raise NotImplementedError

    from_text = classmethod(from_text)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        """Build an rdata object from wire format

        @param rdclass: The rdata class
        @type rdclass: int
        @param rdtype: The rdata type
        @type rdtype: int
        @param wire: The wire-format message
        @type wire: string
        @param current: The offet in wire of the beginning of the rdata.
        @type current: int
        @param rdlen: The length of the wire-format rdata
        @type rdlen: int
        @param origin: The origin to use for relative names
        @type origin: dns.name.Name
        @rtype: dns.rdata.Rdata instance
        """

        raise NotImplementedError

    from_wire = classmethod(from_wire)

    def choose_relativity(self, origin = None, relativize = True):
        """Convert any domain names in the rdata to the specified
        relativization.
        """

        pass


class GenericRdata(Rdata):
    """Generate Rdata Class

    This class is used for rdata types for which we have no better
    implementation.  It implements the DNS "unknown RRs" scheme.
    """

    __slots__ = ['data']

    def __init__(self, rdclass, rdtype, data):
        super(GenericRdata, self).__init__(rdclass, rdtype)
        self.data = data

    def to_text(self, origin=None, relativize=True, **kw):
        return r'\# %d ' % len(self.data) + _hexify(self.data)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        token = tok.get()
        if not token.is_identifier() or token.value != '\#':
            raise dns.exception.SyntaxError(r'generic rdata does not start with \#')
        length = tok.get_int()
        chunks = []
        while 1:
            token = tok.get()
            if token.is_eol_or_eof():
                break
            chunks.append(token.value)
        hex = ''.join(chunks)
        data = hex.decode('hex_codec')
        if len(data) != length:
            raise dns.exception.SyntaxError('generic rdata hex data has wrong length')
        return cls(rdclass, rdtype, data)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        file.write(self.data)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        return cls(rdclass, rdtype, wire[current : current + rdlen])

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        return cmp(self.data, other.data)

_rdata_modules = {}
_module_prefix = 'dns.rdtypes'

def get_rdata_class(rdclass, rdtype):

    def import_module(name):
        mod = __import__(name)
        components = name.split('.')
        for comp in components[1:]:
            mod = getattr(mod, comp)
        return mod

    mod = _rdata_modules.get((rdclass, rdtype))
    rdclass_text = dns.rdataclass.to_text(rdclass)
    rdtype_text = dns.rdatatype.to_text(rdtype)
    rdtype_text = rdtype_text.replace('-', '_')
    if not mod:
        mod = _rdata_modules.get((dns.rdatatype.ANY, rdtype))
        if not mod:
            try:
                mod = import_module('.'.join([_module_prefix,
                                              rdclass_text, rdtype_text]))
                _rdata_modules[(rdclass, rdtype)] = mod
            except ImportError:
                try:
                    mod = import_module('.'.join([_module_prefix,
                                                  'ANY', rdtype_text]))
                    _rdata_modules[(dns.rdataclass.ANY, rdtype)] = mod
                except ImportError:
                    mod = None
    if mod:
        cls = getattr(mod, rdtype_text)
    else:
        cls = GenericRdata
    return cls

def from_text(rdclass, rdtype, tok, origin = None, relativize = True):
    """Build an rdata object from text format.

    This function attempts to dynamically load a class which
    implements the specified rdata class and type.  If there is no
    class-and-type-specific implementation, the GenericRdata class
    is used.

    Once a class is chosen, its from_text() class method is called
    with the parameters to this function.

    If I{tok} is a string, then a tokenizer is created and the string
    is used as its input.

    @param rdclass: The rdata class
    @type rdclass: int
    @param rdtype: The rdata type
    @type rdtype: int
    @param tok: The tokenizer or input text
    @type tok: dns.tokenizer.Tokenizer or string
    @param origin: The origin to use for relative names
    @type origin: dns.name.Name
    @param relativize: Should names be relativized?
    @type relativize: bool
    @rtype: dns.rdata.Rdata instance"""

    if isinstance(tok, str):
        tok = dns.tokenizer.Tokenizer(tok)
    cls = get_rdata_class(rdclass, rdtype)
    if cls != GenericRdata:
        # peek at first token
        token = tok.get()
        tok.unget(token)
        if token.is_identifier() and \
           token.value == r'\#':
            #
            # Known type using the generic syntax.  Extract the
            # wire form from the generic syntax, and then run
            # from_wire on it.
            #
            rdata = GenericRdata.from_text(rdclass, rdtype, tok, origin,
                                           relativize)
            return from_wire(rdclass, rdtype, rdata.data, 0, len(rdata.data),
                             origin)
    return cls.from_text(rdclass, rdtype, tok, origin, relativize)

def from_wire(rdclass, rdtype, wire, current, rdlen, origin = None):
    """Build an rdata object from wire format

    This function attempts to dynamically load a class which
    implements the specified rdata class and type.  If there is no
    class-and-type-specific implementation, the GenericRdata class
    is used.

    Once a class is chosen, its from_wire() class method is called
    with the parameters to this function.

    @param rdclass: The rdata class
    @type rdclass: int
    @param rdtype: The rdata type
    @type rdtype: int
    @param wire: The wire-format message
    @type wire: string
    @param current: The offet in wire of the beginning of the rdata.
    @type current: int
    @param rdlen: The length of the wire-format rdata
    @type rdlen: int
    @param origin: The origin to use for relative names
    @type origin: dns.name.Name
    @rtype: dns.rdata.Rdata instance"""

    wire = dns.wiredata.maybe_wrap(wire)
    cls = get_rdata_class(rdclass, rdtype)
    return cls.from_wire(rdclass, rdtype, wire, current, rdlen, origin)
