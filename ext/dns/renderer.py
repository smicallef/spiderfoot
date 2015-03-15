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

"""Help for building DNS wire format messages"""

import cStringIO
import struct
import random
import time

import dns.exception
import dns.tsig

QUESTION = 0
ANSWER = 1
AUTHORITY = 2
ADDITIONAL = 3

class Renderer(object):
    """Helper class for building DNS wire-format messages.

    Most applications can use the higher-level L{dns.message.Message}
    class and its to_wire() method to generate wire-format messages.
    This class is for those applications which need finer control
    over the generation of messages.

    Typical use::

        r = dns.renderer.Renderer(id=1, flags=0x80, max_size=512)
        r.add_question(qname, qtype, qclass)
        r.add_rrset(dns.renderer.ANSWER, rrset_1)
        r.add_rrset(dns.renderer.ANSWER, rrset_2)
        r.add_rrset(dns.renderer.AUTHORITY, ns_rrset)
        r.add_edns(0, 0, 4096)
        r.add_rrset(dns.renderer.ADDTIONAL, ad_rrset_1)
        r.add_rrset(dns.renderer.ADDTIONAL, ad_rrset_2)
        r.write_header()
        r.add_tsig(keyname, secret, 300, 1, 0, '', request_mac)
        wire = r.get_wire()

    @ivar output: where rendering is written
    @type output: cStringIO.StringIO object
    @ivar id: the message id
    @type id: int
    @ivar flags: the message flags
    @type flags: int
    @ivar max_size: the maximum size of the message
    @type max_size: int
    @ivar origin: the origin to use when rendering relative names
    @type origin: dns.name.Name object
    @ivar compress: the compression table
    @type compress: dict
    @ivar section: the section currently being rendered
    @type section: int (dns.renderer.QUESTION, dns.renderer.ANSWER,
    dns.renderer.AUTHORITY, or dns.renderer.ADDITIONAL)
    @ivar counts: list of the number of RRs in each section
    @type counts: int list of length 4
    @ivar mac: the MAC of the rendered message (if TSIG was used)
    @type mac: string
    """

    def __init__(self, id=None, flags=0, max_size=65535, origin=None):
        """Initialize a new renderer.

        @param id: the message id
        @type id: int
        @param flags: the DNS message flags
        @type flags: int
        @param max_size: the maximum message size; the default is 65535.
        If rendering results in a message greater than I{max_size},
        then L{dns.exception.TooBig} will be raised.
        @type max_size: int
        @param origin: the origin to use when rendering relative names
        @type origin: dns.name.Namem or None.
        """

        self.output = cStringIO.StringIO()
        if id is None:
            self.id = random.randint(0, 65535)
        else:
            self.id = id
        self.flags = flags
        self.max_size = max_size
        self.origin = origin
        self.compress = {}
        self.section = QUESTION
        self.counts = [0, 0, 0, 0]
        self.output.write('\x00' * 12)
        self.mac = ''

    def _rollback(self, where):
        """Truncate the output buffer at offset I{where}, and remove any
        compression table entries that pointed beyond the truncation
        point.

        @param where: the offset
        @type where: int
        """

        self.output.seek(where)
        self.output.truncate()
        keys_to_delete = []
        for k, v in self.compress.iteritems():
            if v >= where:
                keys_to_delete.append(k)
        for k in keys_to_delete:
            del self.compress[k]

    def _set_section(self, section):
        """Set the renderer's current section.

        Sections must be rendered order: QUESTION, ANSWER, AUTHORITY,
        ADDITIONAL.  Sections may be empty.

        @param section: the section
        @type section: int
        @raises dns.exception.FormError: an attempt was made to set
        a section value less than the current section.
        """

        if self.section != section:
            if self.section > section:
                raise dns.exception.FormError
            self.section = section

    def add_question(self, qname, rdtype, rdclass=dns.rdataclass.IN):
        """Add a question to the message.

        @param qname: the question name
        @type qname: dns.name.Name
        @param rdtype: the question rdata type
        @type rdtype: int
        @param rdclass: the question rdata class
        @type rdclass: int
        """

        self._set_section(QUESTION)
        before = self.output.tell()
        qname.to_wire(self.output, self.compress, self.origin)
        self.output.write(struct.pack("!HH", rdtype, rdclass))
        after = self.output.tell()
        if after >= self.max_size:
            self._rollback(before)
            raise dns.exception.TooBig
        self.counts[QUESTION] += 1

    def add_rrset(self, section, rrset, **kw):
        """Add the rrset to the specified section.

        Any keyword arguments are passed on to the rdataset's to_wire()
        routine.

        @param section: the section
        @type section: int
        @param rrset: the rrset
        @type rrset: dns.rrset.RRset object
        """

        self._set_section(section)
        before = self.output.tell()
        n = rrset.to_wire(self.output, self.compress, self.origin, **kw)
        after = self.output.tell()
        if after >= self.max_size:
            self._rollback(before)
            raise dns.exception.TooBig
        self.counts[section] += n

    def add_rdataset(self, section, name, rdataset, **kw):
        """Add the rdataset to the specified section, using the specified
        name as the owner name.

        Any keyword arguments are passed on to the rdataset's to_wire()
        routine.

        @param section: the section
        @type section: int
        @param name: the owner name
        @type name: dns.name.Name object
        @param rdataset: the rdataset
        @type rdataset: dns.rdataset.Rdataset object
        """

        self._set_section(section)
        before = self.output.tell()
        n = rdataset.to_wire(name, self.output, self.compress, self.origin,
                             **kw)
        after = self.output.tell()
        if after >= self.max_size:
            self._rollback(before)
            raise dns.exception.TooBig
        self.counts[section] += n

    def add_edns(self, edns, ednsflags, payload, options=None):
        """Add an EDNS OPT record to the message.

        @param edns: The EDNS level to use.
        @type edns: int
        @param ednsflags: EDNS flag values.
        @type ednsflags: int
        @param payload: The EDNS sender's payload field, which is the maximum
        size of UDP datagram the sender can handle.
        @type payload: int
        @param options: The EDNS options list
        @type options: list of dns.edns.Option instances
        @see: RFC 2671
        """

        # make sure the EDNS version in ednsflags agrees with edns
        ednsflags &= 0xFF00FFFFL
        ednsflags |= (edns << 16)
        self._set_section(ADDITIONAL)
        before = self.output.tell()
        self.output.write(struct.pack('!BHHIH', 0, dns.rdatatype.OPT, payload,
                                      ednsflags, 0))
        if not options is None:
            lstart = self.output.tell()
            for opt in options:
                stuff = struct.pack("!HH", opt.otype, 0)
                self.output.write(stuff)
                start = self.output.tell()
                opt.to_wire(self.output)
                end = self.output.tell()
                assert end - start < 65536
                self.output.seek(start - 2)
                stuff = struct.pack("!H", end - start)
                self.output.write(stuff)
                self.output.seek(0, 2)
            lend = self.output.tell()
            assert lend - lstart < 65536
            self.output.seek(lstart - 2)
            stuff = struct.pack("!H", lend - lstart)
            self.output.write(stuff)
            self.output.seek(0, 2)
        after = self.output.tell()
        if after >= self.max_size:
            self._rollback(before)
            raise dns.exception.TooBig
        self.counts[ADDITIONAL] += 1

    def add_tsig(self, keyname, secret, fudge, id, tsig_error, other_data,
                 request_mac, algorithm=dns.tsig.default_algorithm):
        """Add a TSIG signature to the message.

        @param keyname: the TSIG key name
        @type keyname: dns.name.Name object
        @param secret: the secret to use
        @type secret: string
        @param fudge: TSIG time fudge
        @type fudge: int
        @param id: the message id to encode in the tsig signature
        @type id: int
        @param tsig_error: TSIG error code; default is 0.
        @type tsig_error: int
        @param other_data: TSIG other data.
        @type other_data: string
        @param request_mac: This message is a response to the request which
        had the specified MAC.
        @type request_mac: string
        @param algorithm: the TSIG algorithm to use
        @type algorithm: dns.name.Name object
        """

        self._set_section(ADDITIONAL)
        before = self.output.tell()
        s = self.output.getvalue()
        (tsig_rdata, self.mac, ctx) = dns.tsig.sign(s,
                                                    keyname,
                                                    secret,
                                                    int(time.time()),
                                                    fudge,
                                                    id,
                                                    tsig_error,
                                                    other_data,
                                                    request_mac,
                                                    algorithm=algorithm)
        keyname.to_wire(self.output, self.compress, self.origin)
        self.output.write(struct.pack('!HHIH', dns.rdatatype.TSIG,
                                      dns.rdataclass.ANY, 0, 0))
        rdata_start = self.output.tell()
        self.output.write(tsig_rdata)
        after = self.output.tell()
        assert after - rdata_start < 65536
        if after >= self.max_size:
            self._rollback(before)
            raise dns.exception.TooBig
        self.output.seek(rdata_start - 2)
        self.output.write(struct.pack('!H', after - rdata_start))
        self.counts[ADDITIONAL] += 1
        self.output.seek(10)
        self.output.write(struct.pack('!H', self.counts[ADDITIONAL]))
        self.output.seek(0, 2)

    def write_header(self):
        """Write the DNS message header.

        Writing the DNS message header is done after all sections
        have been rendered, but before the optional TSIG signature
        is added.
        """

        self.output.seek(0)
        self.output.write(struct.pack('!HHHHHH', self.id, self.flags,
                                      self.counts[0], self.counts[1],
                                      self.counts[2], self.counts[3]))
        self.output.seek(0, 2)

    def get_wire(self):
        """Return the wire format message.

        @rtype: string
        """

        return self.output.getvalue()
