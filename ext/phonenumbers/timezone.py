"""Phone number to time zone mapping functionality

>>> import phonenumbers
>>> from phonenumbers.timezone import time_zones_for_number
>>> ro_number = phonenumbers.parse("+40721234567", "RO")
>>> tzlist = time_zones_for_number(ro_number)
>>> len(tzlist)
1
>>> str(tzlist[0])
'Europe/Bucharest'
>>> mx_number = phonenumbers.parse("+523291234567", "GB")
>>> tzlist = time_zones_for_number(mx_number)
>>> len(tzlist)
2
>>> str(tzlist[0])
'America/Mazatlan'
>>> str(tzlist[1])
'America/Mexico_City'

"""
# Based very loosely on original Java code:
#     java/geocoder/src/com/google/i18n/phonenumbers/PhoneNumberToTimeZonesMapper.java
#   Copyright (C) 2013 The Libphonenumber Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from .util import prnt, u, U_PLUS
from .phonenumberutil import PhoneNumberType, number_type
from .phonenumberutil import PhoneNumberFormat, format_number
try:
    from .tzdata import TIMEZONE_DATA, TIMEZONE_LONGEST_PREFIX
except ImportError:  # pragma no cover
    # Before the generated code exists, the carrierdata/ directory is empty.
    # The generation process imports this module, creating a circular
    # dependency.  The hack below works around this.
    import os
    import sys
    if (os.path.basename(sys.argv[0]) == "buildmetadatafromxml.py" or
        os.path.basename(sys.argv[0]) == "buildprefixdata.py"):
        prnt("Failed to import generated data (but OK as during autogeneration)", file=sys.stderr)
        TIMEZONE_DATA = {'4411': u('Europe/London')}
        TIMEZONE_LONGEST_PREFIX = 4
    else:
        raise

__all__ = ['UNKNOWN_TIMEZONE', 'time_zones_for_geographical_number', 'time_zones_for_number']

# This is defined by ICU as the unknown time zone.
UNKNOWN_TIMEZONE = u("Etc/Unknown")
_UNKNOWN_TIME_ZONE_LIST = (UNKNOWN_TIMEZONE,)


def time_zones_for_geographical_number(numobj):
    """Returns a list of time zones to which a phone number belongs.

    This method assumes the validity of the number passed in has already been
    checked, and that the number is geo-localizable. We consider fixed-line
    and mobile numbers possible candidates for geo-localization.

    Arguments:
    numobj -- a valid phone number for which we want to get the time zones
                  to which it belongs
    Returns a list of the corresponding time zones or a single element list
    with the default unknown time zone if no other time zone was found or if
    the number was invalid"""
    e164_num = format_number(numobj, PhoneNumberFormat.E164)
    if not e164_num.startswith(U_PLUS):  # pragma no cover
        # Can only hit this arm if there's an internal error in the rest of
        # the library
        raise Exception("Expect E164 number to start with +")
    for prefix_len in range(TIMEZONE_LONGEST_PREFIX, 0, -1):
        prefix = e164_num[1:(1 + prefix_len)]
        if prefix in TIMEZONE_DATA:
            return TIMEZONE_DATA[prefix]
    return _UNKNOWN_TIME_ZONE_LIST


def time_zones_for_number(numobj):
    """As time_zones_for_geographical_number() but explicitly checks the
    validity of the number passed in.

    Arguments:
    numobj -- a valid phone number for which we want to get the time zones to which it belongs
    Returns a list of the corresponding time zones or a single element list with the default
    unknown time zone if no other time zone was found or if the number was invalid"""
    ntype = number_type(numobj)
    if ntype == PhoneNumberType.UNKNOWN:
        return _UNKNOWN_TIME_ZONE_LIST
    elif not _can_be_geocoded(ntype):
        return _country_level_time_zones_for_number(numobj)
    return time_zones_for_geographical_number(numobj)


def _country_level_time_zones_for_number(numobj):
    """Returns the list of time zones corresponding to the country calling code of a number.
    Arguments:
    numobj -- the phone number to look up
    Returns a list of the corresponding time zones or a single element list with the default
    unknown time zone if no other time zone was found or if the number was invalid"""
    cc = str(numobj.country_code)
    for prefix_len in range(TIMEZONE_LONGEST_PREFIX, 0, -1):
        prefix = cc[:(1 + prefix_len)]
        if prefix in TIMEZONE_DATA:
            return TIMEZONE_DATA[prefix]
    return _UNKNOWN_TIME_ZONE_LIST


# A similar method is implemented as phonenumberutil._is_number_geographical,
# which performs a stricter check, as it determines if a number has a
# geographical association. Also, if new phone number types were added, we
# should check if this other method should be updated too.
# TODO: Remove duplication by completing the login in the method in phonenumberutil.
# For more information, see the comments in that method.
def _can_be_geocoded(ntype):
    return (ntype == PhoneNumberType.FIXED_LINE or
            ntype == PhoneNumberType.MOBILE or
            ntype == PhoneNumberType.FIXED_LINE_OR_MOBILE)


if __name__ == '__main__':  # pragma no cover
    import doctest
    doctest.testmod()
