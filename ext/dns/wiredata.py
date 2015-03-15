# Copyright (C) 2011 Nominum, Inc.
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

"""DNS Wire Data Helper"""

import sys

import dns.exception

class WireData(str):
    # WireData is a string with stricter slicing
    def __getitem__(self, key):
        try:
            return WireData(super(WireData, self).__getitem__(key))
        except IndexError:
            raise dns.exception.FormError
    def __getslice__(self, i, j):
        try:
            if j == sys.maxint:
                # handle the case where the right bound is unspecified
                j = len(self)
            if i < 0 or j < 0:
                raise dns.exception.FormError
            # If it's not an empty slice, access left and right bounds
            # to make sure they're valid
            if i != j:
                super(WireData, self).__getitem__(i)
                super(WireData, self).__getitem__(j - 1)
            return WireData(super(WireData, self).__getslice__(i, j))
        except IndexError:
            raise dns.exception.FormError
    def __iter__(self):
        i = 0
        while 1:
            try:
                yield self[i]
                i += 1
            except dns.exception.FormError:
                raise StopIteration
    def unwrap(self):
        return str(self)

def maybe_wrap(wire):
    if not isinstance(wire, WireData):
        return WireData(wire)
    else:
        return wire
