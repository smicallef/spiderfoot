"""Additional regular expression utilities, to make it easier to sync up
with Java regular expression code.

>>> import re
>>> from .re_util import fullmatch
>>> from .util import u
>>> string = 'abcd'
>>> r1 = re.compile('abcd')
>>> r2 = re.compile('bc')
>>> r3 = re.compile('abc')
>>> fullmatch(r1, string)  # doctest: +ELLIPSIS
<...SRE_Match object...>
>>> fullmatch(r2, string)
>>> fullmatch(r3, string)
>>> r = re.compile('\\d{8}|\\d{10,11}')
>>> m = fullmatch(r, '1234567890')
>>> m.end()
10
>>> r = re.compile(u('[+\uff0b\\d]'), re.UNICODE)
>>> m = fullmatch(r, u('\uff10'))
>>> m.end()
1
"""
import re


def fullmatch(pattern, string, flags=0):
    """Try to apply the pattern at the start of the string, returning a match
    object if the whole string matches, or None if no match was found."""
    # Build a version of the pattern with a non-capturing group around it.
    # This is needed to get m.end() to correctly report the size of the
    # matched expression (as per the final doctest above).
    grouped_pattern = re.compile("^(?:%s)$" % pattern.pattern, pattern.flags)
    m = grouped_pattern.match(string)
    if m and m.end() < len(string):
        # Incomplete match (which should never happen because of the $ at the
        # end of the regexp), treat as failure.
        m = None  # pragma no cover
    return m

if __name__ == '__main__':  # pragma no cover
    import doctest
    doctest.testmod()
