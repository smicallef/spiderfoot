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

"""DNS rdatasets (an rdataset is a set of rdatas of a given type and class)"""

import random
import StringIO
import struct

import dns.exception
import dns.rdatatype
import dns.rdataclass
import dns.rdata
import dns.set

# define SimpleSet here for backwards compatibility
SimpleSet = dns.set.Set

class DifferingCovers(dns.exception.DNSException):
    """Raised if an attempt is made to add a SIG/RRSIG whose covered type
    is not the same as that of the other rdatas in the rdataset."""
    pass

class IncompatibleTypes(dns.exception.DNSException):
    """Raised if an attempt is made to add rdata of an incompatible type."""
    pass

class Rdataset(dns.set.Set):
    """A DNS rdataset.

    @ivar rdclass: The class of the rdataset
    @type rdclass: int
    @ivar rdtype: The type of the rdataset
    @type rdtype: int
    @ivar covers: The covered type.  Usually this value is
    dns.rdatatype.NONE, but if the rdtype is dns.rdatatype.SIG or
    dns.rdatatype.RRSIG, then the covers value will be the rdata
    type the SIG/RRSIG covers.  The library treats the SIG and RRSIG
    types as if they were a family of
    types, e.g. RRSIG(A), RRSIG(NS), RRSIG(SOA).  This makes RRSIGs much
    easier to work with than if RRSIGs covering different rdata
    types were aggregated into a single RRSIG rdataset.
    @type covers: int
    @ivar ttl: The DNS TTL (Time To Live) value
    @type ttl: int
    """

    __slots__ = ['rdclass', 'rdtype', 'covers', 'ttl']

    def __init__(self, rdclass, rdtype, covers=dns.rdatatype.NONE):
        """Create a new rdataset of the specified class and type.

        @see: the description of the class instance variables for the
        meaning of I{rdclass} and I{rdtype}"""

        super(Rdataset, self).__init__()
        self.rdclass = rdclass
        self.rdtype = rdtype
        self.covers = covers
        self.ttl = 0

    def _clone(self):
        obj = super(Rdataset, self)._clone()
        obj.rdclass = self.rdclass
        obj.rdtype = self.rdtype
        obj.covers = self.covers
        obj.ttl = self.ttl
        return obj

    def update_ttl(self, ttl):
        """Set the TTL of the rdataset to be the lesser of the set's current
        TTL or the specified TTL.  If the set contains no rdatas, set the TTL
        to the specified TTL.
        @param ttl: The TTL
        @type ttl: int"""

        if len(self) == 0:
            self.ttl = ttl
        elif ttl < self.ttl:
            self.ttl = ttl

    def add(self, rd, ttl=None):
        """Add the specified rdata to the rdataset.

        If the optional I{ttl} parameter is supplied, then
        self.update_ttl(ttl) will be called prior to adding the rdata.

        @param rd: The rdata
        @type rd: dns.rdata.Rdata object
        @param ttl: The TTL
        @type ttl: int"""

        #
        # If we're adding a signature, do some special handling to
        # check that the signature covers the same type as the
        # other rdatas in this rdataset.  If this is the first rdata
        # in the set, initialize the covers field.
        #
        if self.rdclass != rd.rdclass or self.rdtype != rd.rdtype:
            raise IncompatibleTypes
        if not ttl is None:
            self.update_ttl(ttl)
        if self.rdtype == dns.rdatatype.RRSIG or \
           self.rdtype == dns.rdatatype.SIG:
            covers = rd.covers()
            if len(self) == 0 and self.covers == dns.rdatatype.NONE:
                self.covers = covers
            elif self.covers != covers:
                raise DifferingCovers
        if dns.rdatatype.is_singleton(rd.rdtype) and len(self) > 0:
            self.clear()
        super(Rdataset, self).add(rd)

    def union_update(self, other):
        self.update_ttl(other.ttl)
        super(Rdataset, self).union_update(other)

    def intersection_update(self, other):
        self.update_ttl(other.ttl)
        super(Rdataset, self).intersection_update(other)

    def update(self, other):
        """Add all rdatas in other to self.

        @param other: The rdataset from which to update
        @type other: dns.rdataset.Rdataset object"""

        self.update_ttl(other.ttl)
        super(Rdataset, self).update(other)

    def __repr__(self):
        if self.covers == 0:
            ctext = ''
        else:
            ctext = '(' + dns.rdatatype.to_text(self.covers) + ')'
        return '<DNS ' + dns.rdataclass.to_text(self.rdclass) + ' ' + \
               dns.rdatatype.to_text(self.rdtype) + ctext + ' rdataset>'

    def __str__(self):
        return self.to_text()

    def __eq__(self, other):
        """Two rdatasets are equal if they have the same class, type, and
        covers, and contain the same rdata.
        @rtype: bool"""

        if not isinstance(other, Rdataset):
            return False
        if self.rdclass != other.rdclass or \
           self.rdtype != other.rdtype or \
           self.covers != other.covers:
            return False
        return super(Rdataset, self).__eq__(other)

    def __ne__(self, other):
        return not self.__eq__(other)

    def to_text(self, name=None, origin=None, relativize=True,
                override_rdclass=None, **kw):
        """Convert the rdataset into DNS master file format.

        @see: L{dns.name.Name.choose_relativity} for more information
        on how I{origin} and I{relativize} determine the way names
        are emitted.

        Any additional keyword arguments are passed on to the rdata
        to_text() method.

        @param name: If name is not None, emit a RRs with I{name} as
        the owner name.
        @type name: dns.name.Name object
        @param origin: The origin for relative names, or None.
        @type origin: dns.name.Name object
        @param relativize: True if names should names be relativized
        @type relativize: bool"""
        if not name is None:
            name = name.choose_relativity(origin, relativize)
            ntext = str(name)
            pad = ' '
        else:
            ntext = ''
            pad = ''
        s = StringIO.StringIO()
        if not override_rdclass is None:
            rdclass = override_rdclass
        else:
            rdclass = self.rdclass
        if len(self) == 0:
            #
            # Empty rdatasets are used for the question section, and in
            # some dynamic updates, so we don't need to print out the TTL
            # (which is meaningless anyway).
            #
            print >> s, '%s%s%s %s' % (ntext, pad,
                                       dns.rdataclass.to_text(rdclass),
                                       dns.rdatatype.to_text(self.rdtype))
        else:
            for rd in self:
                print >> s, '%s%s%d %s %s %s' % \
                      (ntext, pad, self.ttl, dns.rdataclass.to_text(rdclass),
                       dns.rdatatype.to_text(self.rdtype),
                       rd.to_text(origin=origin, relativize=relativize, **kw))
        #
        # We strip off the final \n for the caller's convenience in printing
        #
        return s.getvalue()[:-1]

    def to_wire(self, name, file, compress=None, origin=None,
                override_rdclass=None, want_shuffle=True):
        """Convert the rdataset to wire format.

        @param name: The owner name of the RRset that will be emitted
        @type name: dns.name.Name object
        @param file: The file to which the wire format data will be appended
        @type file: file
        @param compress: The compression table to use; the default is None.
        @type compress: dict
        @param origin: The origin to be appended to any relative names when
        they are emitted.  The default is None.
        @returns: the number of records emitted
        @rtype: int
        """

        if not override_rdclass is None:
            rdclass =  override_rdclass
            want_shuffle = False
        else:
            rdclass = self.rdclass
        file.seek(0, 2)
        if len(self) == 0:
            name.to_wire(file, compress, origin)
            stuff = struct.pack("!HHIH", self.rdtype, rdclass, 0, 0)
            file.write(stuff)
            return 1
        else:
            if want_shuffle:
                l = list(self)
                random.shuffle(l)
            else:
                l = self
            for rd in l:
                name.to_wire(file, compress, origin)
                stuff = struct.pack("!HHIH", self.rdtype, rdclass,
                                    self.ttl, 0)
                file.write(stuff)
                start = file.tell()
                rd.to_wire(file, compress, origin)
                end = file.tell()
                assert end - start < 65536
                file.seek(start - 2)
                stuff = struct.pack("!H", end - start)
                file.write(stuff)
                file.seek(0, 2)
            return len(self)

    def match(self, rdclass, rdtype, covers):
        """Returns True if this rdataset matches the specified class, type,
        and covers"""
        if self.rdclass == rdclass and \
           self.rdtype == rdtype and \
           self.covers == covers:
            return True
        return False

def from_text_list(rdclass, rdtype, ttl, text_rdatas):
    """Create an rdataset with the specified class, type, and TTL, and with
    the specified list of rdatas in text format.

    @rtype: dns.rdataset.Rdataset object
    """

    if isinstance(rdclass, (str, unicode)):
        rdclass = dns.rdataclass.from_text(rdclass)
    if isinstance(rdtype, (str, unicode)):
        rdtype = dns.rdatatype.from_text(rdtype)
    r = Rdataset(rdclass, rdtype)
    r.update_ttl(ttl)
    for t in text_rdatas:
        rd = dns.rdata.from_text(r.rdclass, r.rdtype, t)
        r.add(rd)
    return r

def from_text(rdclass, rdtype, ttl, *text_rdatas):
    """Create an rdataset with the specified class, type, and TTL, and with
    the specified rdatas in text format.

    @rtype: dns.rdataset.Rdataset object
    """

    return from_text_list(rdclass, rdtype, ttl, text_rdatas)

def from_rdata_list(ttl, rdatas):
    """Create an rdataset with the specified TTL, and with
    the specified list of rdata objects.

    @rtype: dns.rdataset.Rdataset object
    """

    if len(rdatas) == 0:
        raise ValueError("rdata list must not be empty")
    r = None
    for rd in rdatas:
        if r is None:
            r = Rdataset(rd.rdclass, rd.rdtype)
            r.update_ttl(ttl)
            first_time = False
        r.add(rd)
    return r

def from_rdata(ttl, *rdatas):
    """Create an rdataset with the specified TTL, and with
    the specified rdata objects.

    @rtype: dns.rdataset.Rdataset object
    """

    return from_rdata_list(ttl, rdatas)
