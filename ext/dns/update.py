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

"""DNS Dynamic Update Support"""

import dns.message
import dns.name
import dns.opcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.tsig

class Update(dns.message.Message):
    def __init__(self, zone, rdclass=dns.rdataclass.IN, keyring=None,
                 keyname=None, keyalgorithm=dns.tsig.default_algorithm):
        """Initialize a new DNS Update object.

        @param zone: The zone which is being updated.
        @type zone: A dns.name.Name or string
        @param rdclass: The class of the zone; defaults to dns.rdataclass.IN.
        @type rdclass: An int designating the class, or a string whose value
        is the name of a class.
        @param keyring: The TSIG keyring to use; defaults to None.
        @type keyring: dict
        @param keyname: The name of the TSIG key to use; defaults to None.
        The key must be defined in the keyring.  If a keyring is specified
        but a keyname is not, then the key used will be the first key in the
        keyring.  Note that the order of keys in a dictionary is not defined,
        so applications should supply a keyname when a keyring is used, unless
        they know the keyring contains only one key.
        @type keyname: dns.name.Name or string
        @param keyalgorithm: The TSIG algorithm to use; defaults to
        dns.tsig.default_algorithm.  Constants for TSIG algorithms are defined
        in dns.tsig, and the currently implemented algorithms are
        HMAC_MD5, HMAC_SHA1, HMAC_SHA224, HMAC_SHA256, HMAC_SHA384, and
        HMAC_SHA512.
        @type keyalgorithm: string
        """
        super(Update, self).__init__()
        self.flags |= dns.opcode.to_flags(dns.opcode.UPDATE)
        if isinstance(zone, (str, unicode)):
            zone = dns.name.from_text(zone)
        self.origin = zone
        if isinstance(rdclass, str):
            rdclass = dns.rdataclass.from_text(rdclass)
        self.zone_rdclass = rdclass
        self.find_rrset(self.question, self.origin, rdclass, dns.rdatatype.SOA,
                        create=True, force_unique=True)
        if not keyring is None:
            self.use_tsig(keyring, keyname, algorithm=keyalgorithm)

    def _add_rr(self, name, ttl, rd, deleting=None, section=None):
        """Add a single RR to the update section."""

        if section is None:
            section = self.authority
        covers = rd.covers()
        rrset = self.find_rrset(section, name, self.zone_rdclass, rd.rdtype,
                                covers, deleting, True, True)
        rrset.add(rd, ttl)

    def _add(self, replace, section, name, *args):
        """Add records.  The first argument is the replace mode.  If
        false, RRs are added to an existing RRset; if true, the RRset
        is replaced with the specified contents.  The second
        argument is the section to add to.  The third argument
        is always a name.  The other arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string..."""

        if isinstance(name, (str, unicode)):
            name = dns.name.from_text(name, None)
        if isinstance(args[0], dns.rdataset.Rdataset):
            for rds in args:
                if replace:
                    self.delete(name, rds.rdtype)
                for rd in rds:
                    self._add_rr(name, rds.ttl, rd, section=section)
        else:
            args = list(args)
            ttl = int(args.pop(0))
            if isinstance(args[0], dns.rdata.Rdata):
                if replace:
                    self.delete(name, args[0].rdtype)
                for rd in args:
                    self._add_rr(name, ttl, rd, section=section)
            else:
                rdtype = args.pop(0)
                if isinstance(rdtype, str):
                    rdtype = dns.rdatatype.from_text(rdtype)
                if replace:
                    self.delete(name, rdtype)
                for s in args:
                    rd = dns.rdata.from_text(self.zone_rdclass, rdtype, s,
                                             self.origin)
                    self._add_rr(name, ttl, rd, section=section)

    def add(self, name, *args):
        """Add records.  The first argument is always a name.  The other
        arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string..."""
        self._add(False, self.authority, name, *args)

    def delete(self, name, *args):
        """Delete records.  The first argument is always a name.  The other
        arguments can be:

                - I{nothing}

                - rdataset...

                - rdata...

                - rdtype, [string...]"""

        if isinstance(name, (str, unicode)):
            name = dns.name.from_text(name, None)
        if len(args) == 0:
            rrset = self.find_rrset(self.authority, name, dns.rdataclass.ANY,
                                    dns.rdatatype.ANY, dns.rdatatype.NONE,
                                    dns.rdatatype.ANY, True, True)
        elif isinstance(args[0], dns.rdataset.Rdataset):
            for rds in args:
                for rd in rds:
                    self._add_rr(name, 0, rd, dns.rdataclass.NONE)
        else:
            args = list(args)
            if isinstance(args[0], dns.rdata.Rdata):
                for rd in args:
                    self._add_rr(name, 0, rd, dns.rdataclass.NONE)
            else:
                rdtype = args.pop(0)
                if isinstance(rdtype, (str, unicode)):
                    rdtype = dns.rdatatype.from_text(rdtype)
                if len(args) == 0:
                    rrset = self.find_rrset(self.authority, name,
                                            self.zone_rdclass, rdtype,
                                            dns.rdatatype.NONE,
                                            dns.rdataclass.ANY,
                                            True, True)
                else:
                    for s in args:
                        rd = dns.rdata.from_text(self.zone_rdclass, rdtype, s,
                                                 self.origin)
                        self._add_rr(name, 0, rd, dns.rdataclass.NONE)

    def replace(self, name, *args):
        """Replace records.  The first argument is always a name.  The other
        arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...

        Note that if you want to replace the entire node, you should do
        a delete of the name followed by one or more calls to add."""

        self._add(True, self.authority, name, *args)

    def present(self, name, *args):
        """Require that an owner name (and optionally an rdata type,
        or specific rdataset) exists as a prerequisite to the
        execution of the update.  The first argument is always a name.
        The other arguments can be:

                - rdataset...

                - rdata...

                - rdtype, string..."""

        if isinstance(name, (str, unicode)):
            name = dns.name.from_text(name, None)
        if len(args) == 0:
            rrset = self.find_rrset(self.answer, name,
                                    dns.rdataclass.ANY, dns.rdatatype.ANY,
                                    dns.rdatatype.NONE, None,
                                    True, True)
        elif isinstance(args[0], dns.rdataset.Rdataset) or \
             isinstance(args[0], dns.rdata.Rdata) or \
             len(args) > 1:
            if not isinstance(args[0], dns.rdataset.Rdataset):
                # Add a 0 TTL
                args = list(args)
                args.insert(0, 0)
            self._add(False, self.answer, name, *args)
        else:
            rdtype = args[0]
            if isinstance(rdtype, (str, unicode)):
                rdtype = dns.rdatatype.from_text(rdtype)
            rrset = self.find_rrset(self.answer, name,
                                    dns.rdataclass.ANY, rdtype,
                                    dns.rdatatype.NONE, None,
                                    True, True)

    def absent(self, name, rdtype=None):
        """Require that an owner name (and optionally an rdata type) does
        not exist as a prerequisite to the execution of the update."""

        if isinstance(name, (str, unicode)):
            name = dns.name.from_text(name, None)
        if rdtype is None:
            rrset = self.find_rrset(self.answer, name,
                                    dns.rdataclass.NONE, dns.rdatatype.ANY,
                                    dns.rdatatype.NONE, None,
                                    True, True)
        else:
            if isinstance(rdtype, (str, unicode)):
                rdtype = dns.rdatatype.from_text(rdtype)
            rrset = self.find_rrset(self.answer, name,
                                    dns.rdataclass.NONE, rdtype,
                                    dns.rdatatype.NONE, None,
                                    True, True)

    def to_wire(self, origin=None, max_size=65535):
        """Return a string containing the update in DNS compressed wire
        format.
        @rtype: string"""
        if origin is None:
            origin = self.origin
        return super(Update, self).to_wire(origin, max_size)
