"""Phone number geocoding functionality

>>> import phonenumbers
>>> from phonenumbers.geocoder import description_for_number
>>> from phonenumbers.util import u
>>> gb_number = phonenumbers.parse("+442083612345", "GB")
>>> de_number = phonenumbers.parse("0891234567", "DE")
>>> ch_number = phonenumbers.parse("0431234567", "CH")
>>> str(description_for_number(gb_number, "en"))
'London'
>>> str(description_for_number(gb_number, "fr"))  # fall back to English
'London'
>>> str(description_for_number(gb_number, "en", region="GB"))
'London'
>>> str(description_for_number(gb_number, "en", region="US"))  # fall back to country
'United Kingdom'
>>> str(description_for_number(de_number, "en"))
'Munich'
>>> u('M\u00fcnchen') == description_for_number(de_number, "de")
True
>>> u('Z\u00fcrich') == description_for_number(ch_number, "de")
True
>>> str(description_for_number(ch_number, "en"))
'Zurich'
>>> str(description_for_number(ch_number, "fr"))
'Zurich'
>>> str(description_for_number(ch_number, "it"))
'Zurigo'

"""
# Based very loosely on original Java code:
#     java/src/com/google/i18n/phonenumbers/geocoding/PhoneNumberOfflineGeocoder.java
#   Copyright (C) 2009-2011 The Libphonenumber Authors
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

from .util import prnt, unicod, u, U_EMPTY_STRING, U_ZERO
from .phonenumberutil import region_code_for_number, PhoneNumberType, PhoneNumber
from .phonenumberutil import country_mobile_token, national_significant_number, number_type
from .phonenumberutil import region_code_for_country_code, region_codes_for_country_code
from .phonenumberutil import is_valid_number_for_region, parse, NumberParseException
from .prefix import _prefix_description_for_number
try:
    from .geodata import GEOCODE_DATA, GEOCODE_LONGEST_PREFIX
    from .geodata.locale import LOCALE_DATA
except ImportError:  # pragma no cover
    # Before the generated code exists, the geodata/ directory is empty.
    # The generation process imports this module, creating a circular
    # dependency.  The hack below works around this.
    import os
    import sys
    if (os.path.basename(sys.argv[0]) == "buildmetadatafromxml.py" or
        os.path.basename(sys.argv[0]) == "buildprefixdata.py"):
        prnt("Failed to import generated data (but OK as during autogeneration)", file=sys.stderr)
        GEOCODE_DATA = {'1': {'en': u('United States')}}
        GEOCODE_LONGEST_PREFIX = 1
        LOCALE_DATA = {'US': {'en': u('United States')}}
    else:
        raise

__all__ = ['country_name_for_number', 'description_for_valid_number', 'description_for_number']


def country_name_for_number(numobj, lang, script=None, region=None):
    """Returns the customary display name in the given langauge for the given
    territory the given PhoneNumber object is from.  If it could be from many
    territories, nothing is returned.

    Arguments:
    numobj -- The PhoneNumber object for which we want to get a text description.
    lang -- A 2-letter lowercase ISO 639-1 language code for the language in
                  which the description should be returned (e.g. "en")
    script -- A 4-letter titlecase (first letter uppercase, rest lowercase)
                  ISO script code as defined in ISO 15924, separated by an
                  underscore (e.g. "Hant")
    region --  A 2-letter uppercase ISO 3166-1 country code (e.g. "GB")

    The script and region parameters are currently ignored.

    Returns a text description in the given language code, for the given phone
    number's region, or an empty string if no description is available."""
    region_codes = region_codes_for_country_code(numobj.country_code)
    if len(region_codes) == 1:
        return _region_display_name(region_codes[0], lang, script, region)
    else:
        region_where_number_is_valid = u("ZZ")
        for region_code in region_codes:
            if is_valid_number_for_region(numobj, region_code):
                if region_where_number_is_valid != u("ZZ"):
                    # If we can't assign the phone number as definitely belonging
                    # to only one territory, then we return nothing.
                    return U_EMPTY_STRING
                region_where_number_is_valid = region_code
        return _region_display_name(region_where_number_is_valid, lang, script, region)


def _region_display_name(region_code, lang, script=None, region=None):
    if region_code in LOCALE_DATA:
        # The Locale data has a set of names for this region, in various languages.
        name = LOCALE_DATA[region_code].get(lang, "")
        if name.startswith('*'):
            # If the location name is "*<other_lang>", this indicates that the
            # name is held elsewhere, specifically in the [other_lang] entry
            other_lang = name[1:]
            name = LOCALE_DATA[region_code].get(other_lang, "")
        return unicod(name)
    return U_EMPTY_STRING


def description_for_valid_number(numobj, lang, script=None, region=None):
    """Return a text description of a PhoneNumber object, in the language
    provided.

    The description might consist of the name of the country where the phone
    number is from and/or the name of the geographical area the phone number
    is from if more detailed information is available.

    If the phone number is from the same region as the user, only a
    lower-level description will be returned, if one exists. Otherwise, the
    phone number's region will be returned, with optionally some more detailed
    information.

    For example, for a user from the region "US" (United States), we would
    show "Mountain View, CA" for a particular number, omitting the United
    States from the description. For a user from the United Kingdom (region
    "GB"), for the same number we may show "Mountain View, CA, United States"
    or even just "United States".

    This function assumes the validity of the number passed in has already
    been checked, and that the number is suitable for geocoding.  We consider
    fixed-line and mobile numbers possible candidates for geocoding.

    Arguments:
    numobj -- A valid PhoneNumber object for which we want to get a text
                  description.
    lang -- A 2-letter lowercase ISO 639-1 language code for the language in
                  which the description should be returned (e.g. "en")
    script -- A 4-letter titlecase (first letter uppercase, rest lowercase)
                  ISO script code as defined in ISO 15924, separated by an
                  underscore (e.g. "Hant")
    region -- The region code for a given user. This region will be omitted
                  from the description if the phone number comes from this
                  region. It is a two-letter uppercase ISO country code as
                  defined by ISO 3166-1.

    Returns a text description in the given language code, for the given phone
    number, or an empty string if no description is available."""
    number_region = region_code_for_number(numobj)
    if region is None or region == number_region:
        mobile_token = country_mobile_token(numobj.country_code)
        national_number = national_significant_number(numobj)
        if mobile_token != U_EMPTY_STRING and national_number.startswith(mobile_token):
            # In some countries, eg. Argentina, mobile numbers have a mobile token
            # before the national destination code, this should be removed before
            # geocoding.
            national_number = national_number[len(mobile_token):]

            region = region_code_for_country_code(numobj.country_code)
            try:
                copied_numobj = parse(national_number, region)
            except NumberParseException:
                # If this happens, just re-use what we had.
                copied_numobj = numobj
            area_description = _prefix_description_for_number(GEOCODE_DATA, GEOCODE_LONGEST_PREFIX,
                                                              copied_numobj, lang, script, region)
        else:
            area_description = _prefix_description_for_number(GEOCODE_DATA, GEOCODE_LONGEST_PREFIX,
                                                              numobj, lang, script, region)
        if area_description != "":
            return area_description
        else:
            # Fall back to the description of the number's region
            return country_name_for_number(numobj, lang, script, region)
    else:
        # Otherwise, we just show the region(country) name for now.
        return _region_display_name(number_region, lang, script, region)
        # TODO: Concatenate the lower-level and country-name information in an
        # appropriate way for each language.


def description_for_number(numobj, lang, script=None, region=None):
    """Return a text description of a PhoneNumber object for the given language.

    The description might consist of the name of the country where the phone
    number is from and/or the name of the geographical area the phone number
    is from.  This function explicitly checks the validity of the number passed in

    Arguments:
    numobj -- The PhoneNumber object for which we want to get a text description.
    lang -- A 2-letter lowercase ISO 639-1 language code for the language in
                  which the description should be returned (e.g. "en")
    script -- A 4-letter titlecase (first letter uppercase, rest lowercase)
                  ISO script code as defined in ISO 15924, separated by an
                  underscore (e.g. "Hant")
    region --  A 2-letter uppercase ISO 3166-1 country code (e.g. "GB")

    Returns a text description in the given language code, for the given phone
    number, or an empty string if no description is available."""
    ntype = number_type(numobj)
    if ntype == PhoneNumberType.UNKNOWN:
        return ""
    elif not _can_be_geocoded(ntype):
        return country_name_for_number(numobj, lang, script, region)
    return description_for_valid_number(numobj, lang, script, region)


# A similar method is implemented as phonenumberutil._is_number_geographical,
# which performs a stricter check, as it determines if a number has a
# geographical association. Also, if new phone number types were added, we
# should check if this other method should be updated too.
def _can_be_geocoded(ntype):
    return (ntype == PhoneNumberType.FIXED_LINE or
            ntype == PhoneNumberType.MOBILE or
            ntype == PhoneNumberType.FIXED_LINE_OR_MOBILE)

if __name__ == '__main__':  # pragma no cover
    import doctest
    doctest.testmod()
