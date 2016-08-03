"""Utilities for handling prefix dictionaries"""

from .util import U_EMPTY_STRING, U_PLUS
from .phonenumberutil import format_number, PhoneNumberFormat

_LOCALE_NORMALIZATION_MAP = {"zh_TW": "zh_Hant", "zh_HK": "zh_Hant", "zh_MO": "zh_Hant"}


def _may_fall_back_to_english(lang):
    # Don't fall back to English if the requested language is among the following:
    # - Chinese
    # - Japanese
    # - Korean
    return lang != "zh" and lang != "ja" and lang != "ko"


def _full_locale(lang, script, region):
    if script is not None:
        if region is not None:
            return "%s_%s_%s" % (lang, script, region)
        else:
            return "%s_%s" % (lang, script)
    elif region is not None:
        return "%s_%s" % (lang, region)
    else:
        return lang


def _find_lang(langdict, lang, script, region):
    """Return the entry in the dictionary for the given language information."""
    # Check if we should map this to a different locale.
    full_locale = _full_locale(lang, script, region)
    if (full_locale in _LOCALE_NORMALIZATION_MAP and
        _LOCALE_NORMALIZATION_MAP[full_locale] in langdict):
        return langdict[_LOCALE_NORMALIZATION_MAP[full_locale]]
    # First look for the full locale
    if full_locale in langdict:
        return langdict[full_locale]
    # Then look for lang, script as a combination
    if script is not None:
        lang_script = "%s_%s" % (lang, script)
        if lang_script in langdict:
            return langdict[lang_script]
    # Next look for lang, region as a combination
    if region is not None:
        lang_region = "%s_%s" % (lang, region)
        if lang_region in langdict:
            return langdict[lang_region]
    # Fall back to bare language code lookup
    if lang in langdict:
        return langdict[lang]
    # Possibly fall back to english
    if _may_fall_back_to_english(lang):
        return langdict.get("en", None)
    else:
        return None


def _prefix_description_for_number(data, longest_prefix, numobj, lang, script=None, region=None):
    """Return a text description of a PhoneNumber for the given language.

    Arguments:
    data -- Prefix dictionary to lookup up number in.
    longest_prefix -- Length of the longest key in data.
    numobj -- The PhoneNumber object for which we want to get a text description.
    lang -- A 2-letter lowercase ISO 639-1 language code for the language in
                  which the description should be returned (e.g. "en")
    script -- A 4-letter titlecase (first letter uppercase, rest lowercase)
                  ISO script code as defined in ISO 15924, separated by an
                  underscore (e.g. "Hant")
    region --  A 2-letter uppercase ISO 3166-1 country code (e.g. "GB")

    Returns a text description in the given language code, for the given phone
    number's area, or an empty string if no description is available."""
    e164_num = format_number(numobj, PhoneNumberFormat.E164)
    if not e164_num.startswith(U_PLUS):  # pragma no cover
        # Can only hit this arm if there's an internal error in the rest of
        # the library
        raise Exception("Expect E164 number to start with +")
    for prefix_len in range(longest_prefix, 0, -1):
        prefix = e164_num[1:(1 + prefix_len)]
        if prefix in data:
            # This prefix is present in the geocoding data, as a dictionary
            # mapping language info to location name.
            name = _find_lang(data[prefix], lang, script, region)
            if name is not None:
                return name
            else:
                return U_EMPTY_STRING
    return U_EMPTY_STRING
