"""Phone number to carrier mapping functionality

>>> import phonenumbers
>>> from phonenumbers.carrier import name_for_number
>>> ro_number = phonenumbers.parse("+40721234567", "RO")
>>> str(name_for_number(ro_number, "en"))
'Vodafone'
>>> str(name_for_number(ro_number, "fr"))  # fall back to English
'Vodafone'

"""
# Based very loosely on original Java code:
#     java/carrier/src/com/google/i18n/phonenumbers/PhoneNumberToCarrierMapper.java
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

from .util import prnt, u, U_EMPTY_STRING
from .phonenumberutil import PhoneNumberType, number_type
from .phonenumberutil import region_code_for_number
from .phonenumberutil import is_mobile_number_portable_region
from .prefix import _prefix_description_for_number
try:
    from .carrierdata import CARRIER_DATA, CARRIER_LONGEST_PREFIX
except ImportError:  # pragma no cover
    # Before the generated code exists, the carrierdata/ directory is empty.
    # The generation process imports this module, creating a circular
    # dependency.  The hack below works around this.
    import os
    import sys
    if (os.path.basename(sys.argv[0]) == "buildmetadatafromxml.py" or
        os.path.basename(sys.argv[0]) == "buildprefixdata.py"):
        prnt("Failed to import generated data (but OK as during autogeneration)", file=sys.stderr)
        CARRIER_DATA = {'1': {'en': u('United States')}}
        CARRIER_LONGEST_PREFIX = 1
    else:
        raise


__all__ = ['name_for_valid_number', 'name_for_number', 'safe_display_name']


def name_for_valid_number(numobj, lang, script=None, region=None):
    """Returns a carrier name for the given PhoneNumber object, in the
    language provided.

    The carrier name is the one the number was originally allocated to,
    however if the country supports mobile number portability the number might
    not belong to the returned carrier anymore. If no mapping is found an
    empty string is returned.

    This method assumes the validity of the number passed in has already been
    checked, and that the number is suitable for carrier lookup. We consider
    mobile and pager numbers possible candidates for carrier lookup.

    Arguments:
    numobj -- The PhoneNumber object for which we want to get a carrier name.
    lang -- A 2-letter lowercase ISO 639-1 language code for the language in
                  which the description should be returned (e.g. "en")
    script -- A 4-letter titlecase (first letter uppercase, rest lowercase)
                  ISO script code as defined in ISO 15924, separated by an
                  underscore (e.g. "Hant")
    region --  A 2-letter uppercase ISO 3166-1 country code (e.g. "GB")

    Returns a carrier name in the given language code, for the given phone
    number, or an empty string if no description is available.
    """
    return _prefix_description_for_number(CARRIER_DATA, CARRIER_LONGEST_PREFIX,
                                          numobj, lang, script, region)


def name_for_number(numobj, lang, script=None, region=None):
    """Returns a carrier name for the given PhoneNumber object, in the
    language provided.

    The carrier name is the one the number was originally allocated to,
    however if the country supports mobile number portability the number might
    not belong to the returned carrier anymore. If no mapping is found an
    empty string is returned.

    This function explicitly checks the validity of the number passed in

    Arguments:
    numobj -- The PhoneNumber object for which we want to get a carrier name.
    lang -- A 2-letter lowercase ISO 639-1 language code for the language in
                  which the description should be returned (e.g. "en")
    script -- A 4-letter titlecase (first letter uppercase, rest lowercase)
                  ISO script code as defined in ISO 15924, separated by an
                  underscore (e.g. "Hant")
    region --  A 2-letter uppercase ISO 3166-1 country code (e.g. "GB")

    Returns a carrier name in the given language code, for the given phone
    number, or an empty string if no description is available.
    """
    ntype = number_type(numobj)
    if _is_mobile(ntype):
        return name_for_valid_number(numobj, lang, script, region)
    return U_EMPTY_STRING


def safe_display_name(numobj, lang, script=None, region=None):
    """Gets the name of the carrier for the given PhoneNumber object only when
    it is 'safe' to display to users.  A carrier name is onsidered safe if the
    number is valid and for a region that doesn't support mobile number
    portability (http://en.wikipedia.org/wiki/Mobile_number_portability).


    This function explicitly checks the validity of the number passed in

    Arguments:
    numobj -- The PhoneNumber object for which we want to get a carrier name.
    lang -- A 2-letter lowercase ISO 639-1 language code for the language in
                  which the description should be returned (e.g. "en")
    script -- A 4-letter titlecase (first letter uppercase, rest lowercase)
                  ISO script code as defined in ISO 15924, separated by an
                  underscore (e.g. "Hant")
    region --  A 2-letter uppercase ISO 3166-1 country code (e.g. "GB")

    Returns a carrier name that is safe to display to users, or the empty string.
    """
    if is_mobile_number_portable_region(region_code_for_number(numobj)):
        return U_EMPTY_STRING
    return name_for_number(numobj, lang, script, region)


def _is_mobile(ntype):
    """Checks if the supplied number type supports carrier lookup"""
    return (ntype == PhoneNumberType.MOBILE or
            ntype == PhoneNumberType.FIXED_LINE_OR_MOBILE or
            ntype == PhoneNumberType.PAGER)

if __name__ == '__main__':  # pragma no cover
    import doctest
    doctest.testmod()
