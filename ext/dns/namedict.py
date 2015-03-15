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

"""DNS name dictionary"""

import dns.name

class NameDict(dict):

    """A dictionary whose keys are dns.name.Name objects.
    @ivar max_depth: the maximum depth of the keys that have ever been
    added to the dictionary.
    @type max_depth: int
    """

    def __init__(self, *args, **kwargs):
        super(NameDict, self).__init__(*args, **kwargs)
        self.max_depth = 0

    def __setitem__(self, key, value):
        if not isinstance(key, dns.name.Name):
            raise ValueError('NameDict key must be a name')
        depth = len(key)
        if depth > self.max_depth:
            self.max_depth = depth
        super(NameDict, self).__setitem__(key, value)

    def get_deepest_match(self, name):
        """Find the deepest match to I{name} in the dictionary.

        The deepest match is the longest name in the dictionary which is
        a superdomain of I{name}.

        @param name: the name
        @type name: dns.name.Name object
        @rtype: (key, value) tuple
        """

        depth = len(name)
        if depth > self.max_depth:
            depth = self.max_depth
        for i in xrange(-depth, 0):
            n = dns.name.Name(name[i:])
            if self.has_key(n):
                return (n, self[n])
        v = self[dns.name.empty]
        return (dns.name.empty, v)
