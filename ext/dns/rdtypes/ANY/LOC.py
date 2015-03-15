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

import cStringIO
import struct

import dns.exception
import dns.rdata

_pows = (1L, 10L, 100L, 1000L, 10000L, 100000L, 1000000L, 10000000L,
         100000000L, 1000000000L, 10000000000L)

def _exponent_of(what, desc):
    exp = None
    for i in xrange(len(_pows)):
        if what // _pows[i] == 0L:
            exp = i - 1
            break
    if exp is None or exp < 0:
        raise dns.exception.SyntaxError("%s value out of bounds" % desc)
    return exp

def _float_to_tuple(what):
    if what < 0:
        sign = -1
        what *= -1
    else:
        sign = 1
    what = long(round(what * 3600000))
    degrees = int(what // 3600000)
    what -= degrees * 3600000
    minutes = int(what // 60000)
    what -= minutes * 60000
    seconds = int(what // 1000)
    what -= int(seconds * 1000)
    what = int(what)
    return (degrees * sign, minutes, seconds, what)

def _tuple_to_float(what):
    if what[0] < 0:
        sign = -1
        value = float(what[0]) * -1
    else:
        sign = 1
        value = float(what[0])
    value += float(what[1]) / 60.0
    value += float(what[2]) / 3600.0
    value += float(what[3]) / 3600000.0
    return sign * value

def _encode_size(what, desc):
    what = long(what);
    exponent = _exponent_of(what, desc) & 0xF
    base = what // pow(10, exponent) & 0xF
    return base * 16 + exponent

def _decode_size(what, desc):
    exponent = what & 0x0F
    if exponent > 9:
        raise dns.exception.SyntaxError("bad %s exponent" % desc)
    base = (what & 0xF0) >> 4
    if base > 9:
        raise dns.exception.SyntaxError("bad %s base" % desc)
    return long(base) * pow(10, exponent)

class LOC(dns.rdata.Rdata):
    """LOC record

    @ivar latitude: latitude
    @type latitude: (int, int, int, int) tuple specifying the degrees, minutes,
    seconds, and milliseconds of the coordinate.
    @ivar longitude: longitude
    @type longitude: (int, int, int, int) tuple specifying the degrees,
    minutes, seconds, and milliseconds of the coordinate.
    @ivar altitude: altitude
    @type altitude: float
    @ivar size: size of the sphere
    @type size: float
    @ivar horizontal_precision: horizontal precision
    @type horizontal_precision: float
    @ivar vertical_precision: vertical precision
    @type vertical_precision: float
    @see: RFC 1876"""

    __slots__ = ['latitude', 'longitude', 'altitude', 'size',
                 'horizontal_precision', 'vertical_precision']

    def __init__(self, rdclass, rdtype, latitude, longitude, altitude,
                 size=1.0, hprec=10000.0, vprec=10.0):
        """Initialize a LOC record instance.

        The parameters I{latitude} and I{longitude} may be either a 4-tuple
        of integers specifying (degrees, minutes, seconds, milliseconds),
        or they may be floating point values specifying the number of
        degrees.  The other parameters are floats."""

        super(LOC, self).__init__(rdclass, rdtype)
        if isinstance(latitude, int) or isinstance(latitude, long):
            latitude = float(latitude)
        if isinstance(latitude, float):
            latitude = _float_to_tuple(latitude)
        self.latitude = latitude
        if isinstance(longitude, int) or isinstance(longitude, long):
            longitude = float(longitude)
        if isinstance(longitude, float):
            longitude = _float_to_tuple(longitude)
        self.longitude = longitude
        self.altitude = float(altitude)
        self.size = float(size)
        self.horizontal_precision = float(hprec)
        self.vertical_precision = float(vprec)

    def to_text(self, origin=None, relativize=True, **kw):
        if self.latitude[0] > 0:
            lat_hemisphere = 'N'
            lat_degrees = self.latitude[0]
        else:
            lat_hemisphere = 'S'
            lat_degrees = -1 * self.latitude[0]
        if self.longitude[0] > 0:
            long_hemisphere = 'E'
            long_degrees = self.longitude[0]
        else:
            long_hemisphere = 'W'
            long_degrees = -1 * self.longitude[0]
        text = "%d %d %d.%03d %s %d %d %d.%03d %s %0.2fm" % (
            lat_degrees, self.latitude[1], self.latitude[2], self.latitude[3],
            lat_hemisphere, long_degrees, self.longitude[1], self.longitude[2],
            self.longitude[3], long_hemisphere, self.altitude / 100.0
            )

        if self.size != 1.0 or self.horizontal_precision != 10000.0 or \
           self.vertical_precision != 10.0:
            text += " %0.2fm %0.2fm %0.2fm" % (
                self.size / 100.0, self.horizontal_precision / 100.0,
                self.vertical_precision / 100.0
            )
        return text

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        latitude = [0, 0, 0, 0]
        longitude = [0, 0, 0, 0]
        size = 1.0
        hprec = 10000.0
        vprec = 10.0

        latitude[0] = tok.get_int()
        t = tok.get_string()
        if t.isdigit():
            latitude[1] = int(t)
            t = tok.get_string()
            if '.' in t:
                (seconds, milliseconds) = t.split('.')
                if not seconds.isdigit():
                    raise dns.exception.SyntaxError('bad latitude seconds value')
                latitude[2] = int(seconds)
                if latitude[2] >= 60:
                    raise dns.exception.SyntaxError('latitude seconds >= 60')
                l = len(milliseconds)
                if l == 0 or l > 3 or not milliseconds.isdigit():
                    raise dns.exception.SyntaxError('bad latitude milliseconds value')
                if l == 1:
                    m = 100
                elif l == 2:
                    m = 10
                else:
                    m = 1
                latitude[3] = m * int(milliseconds)
                t = tok.get_string()
            elif t.isdigit():
                latitude[2] = int(t)
                t = tok.get_string()
        if t == 'S':
            latitude[0] *= -1
        elif t != 'N':
            raise dns.exception.SyntaxError('bad latitude hemisphere value')

        longitude[0] = tok.get_int()
        t = tok.get_string()
        if t.isdigit():
            longitude[1] = int(t)
            t = tok.get_string()
            if '.' in t:
                (seconds, milliseconds) = t.split('.')
                if not seconds.isdigit():
                    raise dns.exception.SyntaxError('bad longitude seconds value')
                longitude[2] = int(seconds)
                if longitude[2] >= 60:
                    raise dns.exception.SyntaxError('longitude seconds >= 60')
                l = len(milliseconds)
                if l == 0 or l > 3 or not milliseconds.isdigit():
                    raise dns.exception.SyntaxError('bad longitude milliseconds value')
                if l == 1:
                    m = 100
                elif l == 2:
                    m = 10
                else:
                    m = 1
                longitude[3] = m * int(milliseconds)
                t = tok.get_string()
            elif t.isdigit():
                longitude[2] = int(t)
                t = tok.get_string()
        if t == 'W':
            longitude[0] *= -1
        elif t != 'E':
            raise dns.exception.SyntaxError('bad longitude hemisphere value')

        t = tok.get_string()
        if t[-1] == 'm':
            t = t[0 : -1]
        altitude = float(t) * 100.0	# m -> cm

        token = tok.get().unescape()
        if not token.is_eol_or_eof():
            value = token.value
            if value[-1] == 'm':
                value = value[0 : -1]
            size = float(value) * 100.0	# m -> cm
            token = tok.get().unescape()
            if not token.is_eol_or_eof():
                value = token.value
                if value[-1] == 'm':
                    value = value[0 : -1]
                hprec = float(value) * 100.0	# m -> cm
                token = tok.get().unescape()
                if not token.is_eol_or_eof():
                    value = token.value
                    if value[-1] == 'm':
                        value = value[0 : -1]
                        vprec = float(value) * 100.0	# m -> cm
                        tok.get_eol()

        return cls(rdclass, rdtype, latitude, longitude, altitude,
                   size, hprec, vprec)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        if self.latitude[0] < 0:
            sign = -1
            degrees = long(-1 * self.latitude[0])
        else:
            sign = 1
            degrees = long(self.latitude[0])
        milliseconds = (degrees * 3600000 +
                        self.latitude[1] * 60000 +
                        self.latitude[2] * 1000 +
                        self.latitude[3]) * sign
        latitude = 0x80000000L + milliseconds
        if self.longitude[0] < 0:
            sign = -1
            degrees = long(-1 * self.longitude[0])
        else:
            sign = 1
            degrees = long(self.longitude[0])
        milliseconds = (degrees * 3600000 +
                        self.longitude[1] * 60000 +
                        self.longitude[2] * 1000 +
                        self.longitude[3]) * sign
        longitude = 0x80000000L + milliseconds
        altitude = long(self.altitude) + 10000000L
        size = _encode_size(self.size, "size")
        hprec = _encode_size(self.horizontal_precision, "horizontal precision")
        vprec = _encode_size(self.vertical_precision, "vertical precision")
        wire = struct.pack("!BBBBIII", 0, size, hprec, vprec, latitude,
                           longitude, altitude)
        file.write(wire)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        (version, size, hprec, vprec, latitude, longitude, altitude) = \
                  struct.unpack("!BBBBIII", wire[current : current + rdlen])
        if latitude > 0x80000000L:
            latitude = float(latitude - 0x80000000L) / 3600000
        else:
            latitude = -1 * float(0x80000000L - latitude) / 3600000
        if latitude < -90.0 or latitude > 90.0:
            raise dns.exception.FormError("bad latitude")
        if longitude > 0x80000000L:
            longitude = float(longitude - 0x80000000L) / 3600000
        else:
            longitude = -1 * float(0x80000000L - longitude) / 3600000
        if longitude < -180.0 or longitude > 180.0:
            raise dns.exception.FormError("bad longitude")
        altitude = float(altitude) - 10000000.0
        size = _decode_size(size, "size")
        hprec = _decode_size(hprec, "horizontal precision")
        vprec = _decode_size(vprec, "vertical precision")
        return cls(rdclass, rdtype, latitude, longitude, altitude,
                   size, hprec, vprec)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        f = cStringIO.StringIO()
        self.to_wire(f)
        wire1 = f.getvalue()
        f.seek(0)
        f.truncate()
        other.to_wire(f)
        wire2 = f.getvalue()
        f.close()

        return cmp(wire1, wire2)

    def _get_float_latitude(self):
        return _tuple_to_float(self.latitude)

    def _set_float_latitude(self, value):
        self.latitude = _float_to_tuple(value)

    float_latitude = property(_get_float_latitude, _set_float_latitude,
                              doc="latitude as a floating point value")

    def _get_float_longitude(self):
        return _tuple_to_float(self.longitude)

    def _set_float_longitude(self, value):
        self.longitude = _float_to_tuple(value)

    float_longitude = property(_get_float_longitude, _set_float_longitude,
                               doc="longitude as a floating point value")
