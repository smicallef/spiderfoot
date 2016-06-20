#!/usr/bin/env python
"""Python 2.x/3.x compatibility utilities.

This module defines a collection of functions that allow the same Python
source code to be used in both Python 2.x and Python 3.x.

 - prnt() prints its arguments to a file, with given separator and ending.
 - to_long() creates a (long) integer object from its input parameter.
 - u() allows string literals involving non-ASCII characters to be
   used in both Python 2.x / 3.x, e.g. u("\u0101 is a-with-macron")
 - uchr() generates a single character Unicode string whose point code
   is the given (integer) argument, e.g. uchr(257).
 - unicod() forces its argument to a Unicode string.
 - rpr() generates a representation of a string that can be parsed in either
   Python 2.x or 3.x, assuming use of the u() function above.

>>> from .util import prnt, u, uchr, rpr
>>> prnt("hello")
hello
>>> prnt("hello", "world")
hello world
>>> prnt("hello", "world", sep=":")
hello:world
>>> prnt("hello", "world", sep=":", end='!\\n')
hello:world!
>>> u('\u0101') == uchr(0x0101)
True
>>> u('\u0101') == u('\U00000101')
True
>>> u('\u0101') == u('\N{LATIN SMALL LETTER A WITH MACRON}')
True
>>> a_macron = u('\u0101')
>>> rpr(a_macron)
"u('\\\\u0101')"
>>> rpr(u('abc')) == "'abc'"  # In Python 2, LHS is Unicode but RHS is string
True
>>> rpr("'")
"'\\\\''"
"""
import sys


if sys.version_info >= (3, 0):  # pragma no cover
    import builtins
    print3 = builtins.__dict__['print']

    unicod = str
    u = str
    uchr = chr
    to_long = int

    def prnt(*args, **kwargs):
        sep = kwargs.get('sep', ' ')
        end = kwargs.get('end', '\n')
        file = kwargs.get('file', None)
        print3(*args, **{'sep': sep, 'end': end, 'file': file})

    class UnicodeMixin(object):
        """Mixin class to define a __str__ method in terms of __unicode__ method"""
        __str__ = lambda x: x.__unicode__()

else:  # pragma no cover
    unicod = unicode

    import unicodedata
    import re
    # \N{name} = character named name in the Unicode database
    _UNAME_RE = re.compile(r'\\N\{(?P<name>[^}]+)\}')
    # \uxxxx = character with 16-bit hex value xxxx
    _U16_RE = re.compile(r'\\u(?P<hexval>[0-9a-fA-F]{4})')
    # \Uxxxxxxxx = character with 32-bit hex value xxxxxxxx
    _U32_RE = re.compile(r'\\U(?P<hexval>[0-9a-fA-F]{8})')

    def u(s):
        """Generate Unicode string from a string input, encoding Unicode characters.

        This is expected to work in the same way as u'<string>' would work in Python
        2.x (although it is not completely robust as it is based on a simple set of
        regexps).
        """
        us = re.sub(_U16_RE, lambda m: unichr(int(m.group('hexval'), 16)), unicode(s))
        us = re.sub(_U32_RE, lambda m: unichr(int(m.group('hexval'), 16)), us)
        us = re.sub(_UNAME_RE, lambda m: unicodedata.lookup(m.group('name')), us)
        return us

    uchr = unichr
    to_long = long

    def prnt(*args, **kwargs):
        sep = kwargs.get('sep', ' ')
        end = kwargs.get('end', '\n')
        file = kwargs.get('file', None)
        if file is None:
            file = sys.stdout
        print >> file, sep.join([str(arg) for arg in args]) + end,

    class UnicodeMixin(object):  # pragma no cover
        """Mixin class to define a __str__ method in terms of __unicode__ method"""
        __str__ = lambda x: unicode(x).encode('utf-8')

# Constants for Unicode strings
U_EMPTY_STRING = unicod("")
U_SPACE = unicod(" ")
U_DASH = unicod("-")
U_TILDE = unicod("~")
U_PLUS = unicod("+")
U_STAR = unicod("*")
U_ZERO = unicod("0")
U_SLASH = unicod("/")
U_SEMICOLON = unicod(";")
U_X_LOWER = unicod("x")
U_X_UPPER = unicod("X")
U_PERCENT = unicod("%")


def rpr(s):
    """Create a representation of a Unicode string that can be used in both
    Python 2 and Python 3k, allowing for use of the u() function"""
    if s is None:
        return 'None'
    seen_unicode = False
    results = []
    for cc in s:
        ccn = ord(cc)
        if ccn >= 32 and ccn < 127:
            if cc == "'":  # escape single quote
                results.append('\\')
                results.append(cc)
            elif cc == "\\":  # escape backslash
                results.append('\\')
                results.append(cc)
            else:
                results.append(cc)
        else:
            seen_unicode = True
            if ccn <= 0xFFFF:
                results.append('\\u')
                results.append("%04x" % ccn)
            else:  # pragma no cover
                results.append('\\U')
                results.append("%08x" % ccn)
    result = "'" + "".join(results) + "'"
    if seen_unicode:
        return "u(" + result + ")"
    else:
        return result


def force_unicode(s):
    """Force the argument to be a Unicode string, preserving None"""
    if s is None:
        return None
    else:
        return unicod(s)


class ImmutableMixin(object):
    """Mixin class to make objects of subclasses immutable"""
    _mutable = False

    def __setattr__(self, name, value):
        if self._mutable or name == "_mutable":
            object.__setattr__(self, name, value)
        else:
            raise TypeError("Can't modify immutable instance")

    def __delattr__(self, name):
        if self._mutable:
            object.__delattr__(self, name)
        else:
            raise TypeError("Can't modify immutable instance")


def mutating_method(func):
    """Decorator for methods that are allowed to modify immutable objects"""
    def wrapper(self, *__args, **__kwargs):
        old_mutable = self._mutable
        self._mutable = True
        try:
            # Call the wrapped function
            return func(self, *__args, **__kwargs)
        finally:
            self._mutable = old_mutable
    return wrapper


if __name__ == '__main__':  # pragma no cover
    import doctest
    doctest.testmod()
