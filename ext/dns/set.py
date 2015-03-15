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

"""A simple Set class."""

class Set(object):
    """A simple set class.

    Sets are not in Python until 2.3, and rdata are not immutable so
    we cannot use sets.Set anyway.  This class implements subset of
    the 2.3 Set interface using a list as the container.

    @ivar items: A list of the items which are in the set
    @type items: list"""

    __slots__ = ['items']

    def __init__(self, items=None):
        """Initialize the set.

        @param items: the initial set of items
        @type items: any iterable or None
        """

        self.items = []
        if not items is None:
            for item in items:
                self.add(item)

    def __repr__(self):
        return "dns.simpleset.Set(%s)" % repr(self.items)

    def add(self, item):
        """Add an item to the set."""
        if not item in self.items:
            self.items.append(item)

    def remove(self, item):
        """Remove an item from the set."""
        self.items.remove(item)

    def discard(self, item):
        """Remove an item from the set if present."""
        try:
            self.items.remove(item)
        except ValueError:
            pass

    def _clone(self):
        """Make a (shallow) copy of the set.

        There is a 'clone protocol' that subclasses of this class
        should use.  To make a copy, first call your super's _clone()
        method, and use the object returned as the new instance.  Then
        make shallow copies of the attributes defined in the subclass.

        This protocol allows us to write the set algorithms that
        return new instances (e.g. union) once, and keep using them in
        subclasses.
        """

        cls = self.__class__
        obj = cls.__new__(cls)
        obj.items = list(self.items)
        return obj

    def __copy__(self):
        """Make a (shallow) copy of the set."""
        return self._clone()

    def copy(self):
        """Make a (shallow) copy of the set."""
        return self._clone()

    def union_update(self, other):
        """Update the set, adding any elements from other which are not
        already in the set.
        @param other: the collection of items with which to update the set
        @type other: Set object
        """
        if not isinstance(other, Set):
            raise ValueError('other must be a Set instance')
        if self is other:
            return
        for item in other.items:
            self.add(item)

    def intersection_update(self, other):
        """Update the set, removing any elements from other which are not
        in both sets.
        @param other: the collection of items with which to update the set
        @type other: Set object
        """
        if not isinstance(other, Set):
            raise ValueError('other must be a Set instance')
        if self is other:
            return
        # we make a copy of the list so that we can remove items from
        # the list without breaking the iterator.
        for item in list(self.items):
            if item not in other.items:
                self.items.remove(item)

    def difference_update(self, other):
        """Update the set, removing any elements from other which are in
        the set.
        @param other: the collection of items with which to update the set
        @type other: Set object
        """
        if not isinstance(other, Set):
            raise ValueError('other must be a Set instance')
        if self is other:
            self.items = []
        else:
            for item in other.items:
                self.discard(item)

    def union(self, other):
        """Return a new set which is the union of I{self} and I{other}.

        @param other: the other set
        @type other: Set object
        @rtype: the same type as I{self}
        """

        obj = self._clone()
        obj.union_update(other)
        return obj

    def intersection(self, other):
        """Return a new set which is the intersection of I{self} and I{other}.

        @param other: the other set
        @type other: Set object
        @rtype: the same type as I{self}
        """

        obj = self._clone()
        obj.intersection_update(other)
        return obj

    def difference(self, other):
        """Return a new set which I{self} - I{other}, i.e. the items
        in I{self} which are not also in I{other}.

        @param other: the other set
        @type other: Set object
        @rtype: the same type as I{self}
        """

        obj = self._clone()
        obj.difference_update(other)
        return obj

    def __or__(self, other):
        return self.union(other)

    def __and__(self, other):
        return self.intersection(other)

    def __add__(self, other):
        return self.union(other)

    def __sub__(self, other):
        return self.difference(other)

    def __ior__(self, other):
        self.union_update(other)
        return self

    def __iand__(self, other):
        self.intersection_update(other)
        return self

    def __iadd__(self, other):
        self.union_update(other)
        return self

    def __isub__(self, other):
        self.difference_update(other)
        return self

    def update(self, other):
        """Update the set, adding any elements from other which are not
        already in the set.
        @param other: the collection of items with which to update the set
        @type other: any iterable type"""
        for item in other:
            self.add(item)

    def clear(self):
        """Make the set empty."""
        self.items = []

    def __eq__(self, other):
        # Yes, this is inefficient but the sets we're dealing with are
        # usually quite small, so it shouldn't hurt too much.
        for item in self.items:
            if not item in other.items:
                return False
        for item in other.items:
            if not item in self.items:
                return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)

    def __len__(self):
        return len(self.items)

    def __iter__(self):
        return iter(self.items)

    def __getitem__(self, i):
        return self.items[i]

    def __delitem__(self, i):
        del self.items[i]

    def __getslice__(self, i, j):
        return self.items[i:j]

    def __delslice__(self, i, j):
        del self.items[i:j]

    def issubset(self, other):
        """Is I{self} a subset of I{other}?

        @rtype: bool
        """

        if not isinstance(other, Set):
            raise ValueError('other must be a Set instance')
        for item in self.items:
            if not item in other.items:
                return False
        return True

    def issuperset(self, other):
        """Is I{self} a superset of I{other}?

        @rtype: bool
        """

        if not isinstance(other, Set):
            raise ValueError('other must be a Set instance')
        for item in other.items:
            if not item in self.items:
                return False
        return True
