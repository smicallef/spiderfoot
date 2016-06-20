"""A formatter which formats phone numbers as they are entered.

An AsYouTypeFormatter can be created by invoking
AsYouTypeFormatter(region_code). After that digits can be added by invoking
input_digit() on the formatter instance, and the partially formatted phone
number will be returned each time a digit is added. clear() should be invoked
before a new number needs to be formatted.

See the unit tests for more details on how the formatter is to be used.
"""

# Based on original Java code:
#     java/src/com/google/i18n/phonenumbers/AsYouTypeFormatter.java
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
import re

from .util import u, unicod, U_EMPTY_STRING, U_SPACE
from .unicode_util import digit as unicode_digit
from .re_util import fullmatch
from .phonemetadata import PhoneMetadata
from .phonenumberutil import _VALID_PUNCTUATION, REGION_CODE_FOR_NON_GEO_ENTITY
from .phonenumberutil import _PLUS_SIGN, _PLUS_CHARS_PATTERN
from .phonenumberutil import _extract_country_code, region_code_for_country_code
from .phonenumberutil import country_code_for_region
from .phonenumberutil import _formatting_rule_has_first_group_only

# Character used when appropriate to separate a prefix, such as a long NDD or
# a country calling code, from the national number.
_SEPARATOR_BEFORE_NATIONAL_NUMBER = U_SPACE
_EMPTY_METADATA = PhoneMetadata(id=unicod(""),
                                international_prefix=unicod("NA"),
                                register=False)

# A pattern that is used to match character classes in regular expressions. An
# example of a character class is [1-4].
_CHARACTER_CLASS_PATTERN = re.compile(unicod("\\[([^\\[\\]])*\\]"))
# Any digit in a regular expression that actually denotes a digit. For
# example, in the regular expression 80[0-2]\d{6,10}, the first 2 digits (8
# and 0) are standalone digits, but the rest are not.
# Two look-aheads are needed because the number following \\d could be a
# two-digit number, since the phone number can be as long as 15 digits.
_STANDALONE_DIGIT_PATTERN = re.compile(unicod("\\d(?=[^,}][^,}])"))

# A set of characters that, if found in a national prefix formatting rules, are an indicator to
# us that we should separate the national prefix from the number when formatting.
_NATIONAL_PREFIX_SEPARATORS_PATTERN = re.compile("[- ]")

# A pattern that is used to determine if a number_format under
# available_formats is eligible to be used by the AYTF. It is eligible when
# the format element under number_format contains groups of the dollar sign
# followed by a single digit, separated by valid phone number
# punctuation. This prevents invalid punctuation (such as the star sign in
# Israeli star numbers) getting into the output of the AYTF.
_ELIGIBLE_FORMAT_PATTERN = re.compile(unicod("[") + _VALID_PUNCTUATION + unicod("]*") +
                                      unicod("(\\\\\\d") + unicod("[") + _VALID_PUNCTUATION + unicod("]*)+"))

# This is the minimum length of national number accrued that is required to
# trigger the formatter. The first element of the leading_digits_pattern of each
# number_format contains a regular expression that matches up to this number of
# digits.
_MIN_LEADING_DIGITS_LENGTH = 3
# The digits that have not been entered yet will be represented by a \u2008,
# the punctuation space.
_DIGIT_PLACEHOLDER = u("\u2008")
_DIGIT_PATTERN = re.compile(_DIGIT_PLACEHOLDER)


def _get_metadata_for_region(region_code):
    """The metadata needed by this class is the same for all regions
    sharing the same country calling code. Therefore, we return the
    metadata for "main" region for this country calling code."""
    country_calling_code = country_code_for_region(region_code)
    main_country = region_code_for_country_code(country_calling_code)
    # Set to a default instance of the metadata. This allows us to
    # function with an incorrect region code, even if formatting only
    # works for numbers specified with "+".
    return PhoneMetadata.metadata_for_region(main_country, _EMPTY_METADATA)


class AsYouTypeFormatter(object):
    def __init__(self, region_code):
        """Gets an AsYouTypeFormatter for the specific region.

        Arguments:
        region_code -- The region where the phone number is being entered

        Return an AsYouTypeFormatter} object, which could be used to format
        phone numbers in the specific region "as you type"
        """
        self._clear()
        self._default_country = region_code.upper()
        self._current_metadata = _get_metadata_for_region(self._default_country)
        self._default_metadata = self._current_metadata

    def _maybe_create_new_template(self):
        """Returns True if a new template is created as opposed to reusing the existing template.

        When there are multiple available formats, the formatter uses the
        first format where a formatting template could be created.
        """
        ii = 0
        while ii < len(self._possible_formats):
            number_format = self._possible_formats[ii]
            pattern = number_format.pattern
            if self._current_formatting_pattern == pattern:
                return False
            if self._create_formatting_template(number_format):
                self._current_formatting_pattern = pattern
                if number_format.national_prefix_formatting_rule is None:
                    self._should_add_space_after_national_prefix = False
                else:
                    self._should_add_space_after_national_prefix = bool(_NATIONAL_PREFIX_SEPARATORS_PATTERN.search(number_format.national_prefix_formatting_rule))
                # With a new formatting template, the matched position using
                # the old template needs to be reset.
                self._last_match_position = 0
                return True
            else:
                # Remove the current number format from _possible_formats
                del self._possible_formats[ii]
                ii -= 1
            ii += 1
        self._able_to_format = False
        return False

    def _get_available_formats(self, leading_digits):
        if (self._is_complete_number and
            len(self._current_metadata.intl_number_format) > 0):
            number_formats = self._current_metadata.intl_number_format
        else:
            number_formats = self._current_metadata.number_format
        national_prefix_is_used_by_country = (self._current_metadata.national_prefix is not None)
        for this_format in number_formats:
            if (not national_prefix_is_used_by_country or self._is_complete_number or
                this_format.national_prefix_optional_when_formatting or
                _formatting_rule_has_first_group_only(this_format.national_prefix_formatting_rule)):
                if self._is_format_eligible(this_format.format):
                    self._possible_formats.append(this_format)
        self._narrow_down_possible_formats(leading_digits)

    def _is_format_eligible(self, format):
        return fullmatch(_ELIGIBLE_FORMAT_PATTERN, format)

    def _narrow_down_possible_formats(self, leading_digits):
        index_of_leading_digits_pattern = len(leading_digits) - _MIN_LEADING_DIGITS_LENGTH
        ii = 0
        while ii < len(self._possible_formats):
            num_format = self._possible_formats[ii]
            ii += 1
            if len(num_format.leading_digits_pattern) == 0:
                # Keep everything that isn't restricted by leading digits.
                continue
            last_leading_digits_pattern = min(index_of_leading_digits_pattern,
                                              len(num_format.leading_digits_pattern) - 1)
            leading_digits_pattern = re.compile(num_format.leading_digits_pattern[last_leading_digits_pattern])
            m = leading_digits_pattern.match(leading_digits)
            if not m:
                # remove the element we've just examined, now at (ii-1)
                ii -= 1
                self._possible_formats.pop(ii)

    def _create_formatting_template(self, num_format):
        number_pattern = num_format.pattern

        # The formatter doesn't format numbers when number_pattern contains
        # "|", e.g.  (20|3)\d{4}. In those cases we quickly return.
        if number_pattern.find('|') != -1:
            return False

        # Replace anything in the form of [..] with \d
        number_pattern = re.sub(_CHARACTER_CLASS_PATTERN, unicod("\\\\d"), number_pattern)

        # Replace any standalone digit (not the one in d{}) with \d
        number_pattern = re.sub(_STANDALONE_DIGIT_PATTERN, unicod("\\\\d"), number_pattern)
        self.formatting_template = U_EMPTY_STRING
        temp_template = self._get_formatting_template(number_pattern, num_format.format)
        if len(temp_template) > 0:
            self._formatting_template = temp_template
            return True
        return False

    def _get_formatting_template(self, number_pattern, number_format):
        """Gets a formatting template which can be used to efficiently
        format a partial number where digits are added one by one."""
        # Create a phone number consisting only of the digit 9 that matches the
        # number_pattern by applying the pattern to the longest_phone_number string.
        longest_phone_number = unicod("999999999999999")
        number_re = re.compile(number_pattern)
        m = number_re.search(longest_phone_number)  # this will always succeed
        a_phone_number = m.group(0)
        # No formatting template can be created if the number of digits
        # entered so far is longer than the maximum the current formatting
        # rule can accommodate.
        if len(a_phone_number) < len(self._national_number):
            return U_EMPTY_STRING
        # Formats the number according to number_format
        template = re.sub(number_pattern, number_format, a_phone_number)
        # Replaces each digit with character _DIGIT_PLACEHOLDER
        template = re.sub("9", _DIGIT_PLACEHOLDER, template)
        return template

    def _clear(self):
        """Clears the internal state of the formatter, so it can be reused."""
        self._current_output = U_EMPTY_STRING
        self._accrued_input = U_EMPTY_STRING
        self._accrued_input_without_formatting = U_EMPTY_STRING
        self._formatting_template = U_EMPTY_STRING
        self._last_match_position = 0

        # The pattern from number_format that is currently used to create
        # formatting_template.
        self._current_formatting_pattern = U_EMPTY_STRING
        # This contains anything that has been entered so far preceding the
        # national significant number, and it is formatted (e.g. with space
        # inserted). For example, this can contain IDD, country code, and/or
        # NDD, etc.
        self._prefix_before_national_number = U_EMPTY_STRING
        self._should_add_space_after_national_prefix = False
        # This contains the national prefix that has been extracted. It
        # contains only digits without formatting.
        self._extracted_national_prefix = U_EMPTY_STRING
        self._national_number = U_EMPTY_STRING
        # This indicates whether AsYouTypeFormatter is currently doing the
        # formatting.
        self._able_to_format = True
        # Set to true when users enter their own
        # formatting. AsYouTypeFormatter will do no formatting at all when
        # this is set to True.
        self._input_has_formatting = False
        # The position of a digit upon which input_digit(remember_position=True) is
        # most recently invoked, as found in accrued_input_without_formatting.
        self._position_to_remember = 0
        # The position of a digit upon which input_digit(remember_position=True) is
        # most recently invoked, as found in the original sequence of
        # characters the user entered.
        self._original_position = 0
        # This is set to true when we know the user is entering a full
        # national significant number, since we have either detected a
        # national prefix or an international dialing prefix. When this is
        # true, we will no longer use local number formatting patterns.
        self._is_complete_number = False
        self._is_expecting_country_calling_code = False
        self._possible_formats = []

    def clear(self):
        """Clears the internal state of the formatter, so it can be reused."""
        self._clear()
        if self._current_metadata != self._default_metadata:
            self._current_metadata = _get_metadata_for_region(self._default_country)

    def input_digit(self, next_char, remember_position=False):
        """Formats a phone number on-the-fly as each digit is entered.

        If remember_position is set, remembers the position where next_char is
        inserted, so that it can be retrieved later by using
        get_remembered_position. The remembered position will be automatically
        adjusted if additional formatting characters are later
        inserted/removed in front of next_char.

        Arguments:

        next_char -- The most recently entered digit of a phone
              number. Formatting characters are allowed, but as soon as they
              are encountered this method formats the number as entered and
              not "as you type" anymore. Full width digits and Arabic-indic
              digits are allowed, and will be shown as they are.
        remember_position -- Whether to track the position where next_char is
              inserted.

        Returns the partially formatted phone number.
        """
        self._accrued_input += next_char
        if remember_position:
            self._original_position = len(self._accrued_input)
        # We do formatting on-the-fly only when each character entered is
        # either a digit, or a plus sign (accepted at the start of the number
        # only).
        if not self._is_digit_or_leading_plus_sign(next_char):
            self._able_to_format = False
            self._input_has_formatting = True
        else:
            next_char = self._normalize_and_accrue_digits_and_plus_sign(next_char, remember_position)
        if not self._able_to_format:
            # When we are unable to format because of reasons other than that
            # formatting chars have been entered, it can be due to really long
            # IDDs or NDDs. If that is the case, we might be able to do
            # formatting again after extracting them.
            if self._input_has_formatting:
                self._current_output = self._accrued_input
                return self._current_output
            elif self._attempt_to_extract_idd():
                if self._attempt_to_extract_ccc():
                    self._current_output = self._attempt_to_choose_pattern_with_prefix_extracted()
                    return self._current_output
            elif self._able_to_extract_longer_ndd():
                # Add an additional space to separate long NDD and national
                # significant number for readability. We don't set
                # should_add_space_after_national_prefix to True, since we don't
                # want this to change later when we choose formatting
                # templates.
                self._prefix_before_national_number += _SEPARATOR_BEFORE_NATIONAL_NUMBER
                self._current_output = self._attempt_to_choose_pattern_with_prefix_extracted()
                return self._current_output

            self._current_output = self._accrued_input
            return self._current_output

        # We start to attempt to format only when at least
        # MIN_LEADING_DIGITS_LENGTH digits (the plus sign is counted as a
        # digit as well for this purpose) have been entered.
        len_input = len(self._accrued_input_without_formatting)
        if len_input >= 0 and len_input <= 2:
            self._current_output = self._accrued_input
            return self._current_output
        elif len_input == 3:
            if self._attempt_to_extract_idd():
                self._is_expecting_country_calling_code = True
            else:
                # No IDD or plus sign is found, might be entering in national format.
                self._extracted_national_prefix = self._remove_national_prefix_from_national_number()
                self._current_output = self._attempt_to_choose_formatting_pattern()
                return self._current_output
        if self._is_expecting_country_calling_code:
            if self._attempt_to_extract_ccc():
                self._is_expecting_country_calling_code = False
            self._current_output = self._prefix_before_national_number + self._national_number
            return self._current_output

        if len(self._possible_formats) > 0:  # The formatting patterns are already chosen.
            temp_national_number = self._input_digit_helper(next_char)
            # See if the accrued digits can be formatted properly already. If
            # not, use the results from input_digit_helper, which does
            # formatting based on the formatting pattern chosen.
            formatted_number = self._attempt_to_format_accrued_digits()
            if len(formatted_number) > 0:
                self._current_output = formatted_number
                return self._current_output
            self._narrow_down_possible_formats(self._national_number)
            if self._maybe_create_new_template():
                self._current_output = self._input_accrued_national_number()
                return self._current_output
            if self._able_to_format:
                self._current_output = self._append_national_number(temp_national_number)
                return self._current_output
            else:
                self._current_output = self._accrued_input
                return self._current_output
        else:
            self._current_output = self._attempt_to_choose_formatting_pattern()
            return self._current_output

    def _attempt_to_choose_pattern_with_prefix_extracted(self):
        self._able_to_format = True
        self._is_expecting_country_calling_code = False
        self._possible_formats = []
        self._last_match_position = 0
        self._formatting_template = U_EMPTY_STRING
        self._current_formatting_pattern = U_EMPTY_STRING
        return self._attempt_to_choose_formatting_pattern()

    # Some national prefixes are a substring of others. If extracting the
    # shorter NDD doesn't result in a number we can format, we try to see if
    # we can extract a longer version here.
    def _able_to_extract_longer_ndd(self):
        if len(self._extracted_national_prefix) > 0:
            # Put the extracted NDD back to the national number before
            # attempting to extract a new NDD.
            self._national_number = self._extracted_national_prefix + self._national_number
            # Remove the previously extracted NDD from
            # prefixBeforeNationalNumber. We cannot simply set it to empty
            # string because people sometimes incorrectly enter national
            # prefix after the country code, e.g. +44 (0)20-1234-5678.
            index_of_previous_ndd = self._prefix_before_national_number.rfind(self._extracted_national_prefix)
            self._prefix_before_national_number = self._prefix_before_national_number[:index_of_previous_ndd]
        return self._extracted_national_prefix != self._remove_national_prefix_from_national_number()

    def _is_digit_or_leading_plus_sign(self, next_char):
        return (next_char.isdigit() or
                (len(self._accrued_input) == 1 and
                 fullmatch(_PLUS_CHARS_PATTERN, next_char)))

    def _attempt_to_format_accrued_digits(self):
        """Check to see if there is an exact pattern match for these digits. If so, we should use this
        instead of any other formatting template whose leadingDigitsPattern also matches the input.
        """
        for number_format in self._possible_formats:
            num_re = re.compile(number_format.pattern)
            if fullmatch(num_re, self._national_number):
                if number_format.national_prefix_formatting_rule is None:
                    self._should_add_space_after_national_prefix = False
                else:
                    self._should_add_space_after_national_prefix = bool(_NATIONAL_PREFIX_SEPARATORS_PATTERN.search(number_format.national_prefix_formatting_rule))
                formatted_number = re.sub(num_re, number_format.format, self._national_number)
                return self._append_national_number(formatted_number)
        return U_EMPTY_STRING

    def get_remembered_position(self):
        """Returns the current position in the partially formatted phone
        number of the character which was previously passed in as the
        parameter of input_digit(remember_position=True)."""
        if not self._able_to_format:
            return self._original_position
        accrued_input_index = 0
        current_output_index = 0
        while (accrued_input_index < self._position_to_remember and
               current_output_index < len(self._current_output)):
            if (self._accrued_input_without_formatting[accrued_input_index] ==
                self._current_output[current_output_index]):
                accrued_input_index += 1
            current_output_index += 1
        return current_output_index

    def _append_national_number(self, national_number):
        """Combines the national number with any prefix (IDD/+ and country
        code or national prefix) that was collected. A space will be inserted
        between them if the current formatting template indicates this to be
        suitable.
        """
        prefix_before_nn_len = len(self._prefix_before_national_number)
        if (self._should_add_space_after_national_prefix and prefix_before_nn_len > 0 and
            self._prefix_before_national_number[-1] != _SEPARATOR_BEFORE_NATIONAL_NUMBER):
            # We want to add a space after the national prefix if the national
            # prefix formatting rule indicates that this would normally be
            # done, with the exception of the case where we already appended a
            # space because the NDD was surprisingly long.
            return self._prefix_before_national_number + _SEPARATOR_BEFORE_NATIONAL_NUMBER + national_number
        else:
            return self._prefix_before_national_number + national_number

    def _attempt_to_choose_formatting_pattern(self):
        """Attempts to set the formatting template and returns a string which
        contains the formatted version of the digits entered so far."""
        # We start to attempt to format only when at least MIN_LEADING_DIGITS_LENGTH digits of national
        # number (excluding national prefix) have been entered.
        if len(self._national_number) >= _MIN_LEADING_DIGITS_LENGTH:
            self._get_available_formats(self._national_number)
            # See if the accrued digits can be formatted properly already.
            formatted_number = self._attempt_to_format_accrued_digits()
            if len(formatted_number) > 0:
                return formatted_number
            if self._maybe_create_new_template():
                return self._input_accrued_national_number()
            else:
                return self._accrued_input
        else:
            return self._append_national_number(self._national_number)

    def _input_accrued_national_number(self):
        """Invokes input_digit_helper on each digit of the national number
        accrued, and returns a formatted string in the end."""
        length_of_national_number = len(self._national_number)
        if length_of_national_number > 0:
            temp_national_number = U_EMPTY_STRING
            for ii in range(length_of_national_number):
                temp_national_number = self._input_digit_helper(self._national_number[ii])
            if self._able_to_format:
                return self._append_national_number(temp_national_number)
            else:
                return self._accrued_input
        else:
            return self._prefix_before_national_number

    def _is_nanpa_number_with_national_prefix(self):
        """Returns true if the current country is a NANPA country and the
        national number begins with the national prefix.
        """
        # For NANPA numbers beginning with 1[2-9], treat the 1 as the national
        # prefix. The reason is that national significant numbers in NANPA
        # always start with [2-9] after the national prefix.  Numbers
        # beginning with 1[01] can only be short/emergency numbers, which
        # don't need the national prefix.
        return (self._current_metadata.country_code == 1 and self._national_number[0] == '1' and
                self._national_number[1] != '0' and self._national_number[1] != '1')

    def _remove_national_prefix_from_national_number(self):
        start_of_national_number = 0
        if self._is_nanpa_number_with_national_prefix():
            start_of_national_number = 1
            self._prefix_before_national_number += unicod("1") + _SEPARATOR_BEFORE_NATIONAL_NUMBER
            self._is_complete_number = True
        elif self._current_metadata.national_prefix_for_parsing is not None:
            npp_re = re.compile(self._current_metadata.national_prefix_for_parsing)
            m = npp_re.match(self._national_number)
            # Since some national prefix patterns are entirely optional, check
            # that a national prefix could actually be extracted.
            if m and m.end() > 0:
                # When the national prefix is detected, we use international
                # formatting rules instead of national ones, because national
                # formatting rules could contain local formatting rules for
                # numbers entered without area code.
                self._is_complete_number = True
                start_of_national_number = m.end()
                self._prefix_before_national_number += self._national_number[:start_of_national_number]
        national_prefix = self._national_number[:start_of_national_number]
        self._national_number = self._national_number[start_of_national_number:]
        return national_prefix

    def _attempt_to_extract_idd(self):
        """Extracts IDD and plus sign to self._prefix_before_national_number
        when they are available, and places the remaining input into
        _national_number.

        Returns True when accrued_input_without_formatting begins with the plus sign or valid IDD for
        default_country.
        """
        international_prefix = re.compile(unicod("\\") + _PLUS_SIGN + unicod("|") +
                                          (self._current_metadata.international_prefix or U_EMPTY_STRING))
        idd_match = international_prefix.match(self._accrued_input_without_formatting)
        if idd_match:
            self._is_complete_number = True
            start_of_country_calling_code = idd_match.end()
            self._national_number = self._accrued_input_without_formatting[start_of_country_calling_code:]
            self._prefix_before_national_number = self._accrued_input_without_formatting[:start_of_country_calling_code]
            if self._accrued_input_without_formatting[0] != _PLUS_SIGN:
                self._prefix_before_national_number += _SEPARATOR_BEFORE_NATIONAL_NUMBER
            return True
        return False

    def _attempt_to_extract_ccc(self):
        """Extracts the country calling code from the beginning of
        _national_number to _prefix_before_national_number when they are
        available, and places the remaining input into _national_number.

        Returns True when a valid country calling code can be found.
        """
        if len(self._national_number) == 0:
            return False

        country_code, number_without_ccc = _extract_country_code(self._national_number)
        if country_code == 0:
            return False

        self._national_number = number_without_ccc
        new_region_code = region_code_for_country_code(country_code)
        if new_region_code == REGION_CODE_FOR_NON_GEO_ENTITY:
            self._current_metadata = PhoneMetadata.metadata_for_nongeo_region(country_code)
        elif new_region_code != self._default_country:
            self._current_metadata = _get_metadata_for_region(new_region_code)

        self._prefix_before_national_number += str(country_code)
        self._prefix_before_national_number += _SEPARATOR_BEFORE_NATIONAL_NUMBER
        # When we have successfully extracted the IDD, the previously
        # extracted NDD should be cleared because it is no longer valid.
        self._extracted_national_prefix = U_EMPTY_STRING
        return True

    def _normalize_and_accrue_digits_and_plus_sign(self, next_char, remember_position):
        """Accrues digits and the plus sign to
        _accrued_input_without_formatting for later use. If next_char contains
        a digit in non-ASCII format (e.g. the full-width version of digits),
        it is first normalized to the ASCII version. The return value is
        next_char itself, or its normalized version, if next_char is a digit
        in non-ASCII format. This method assumes its input is either a digit
        or the plus sign."""
        if next_char == _PLUS_SIGN:
            normalized_char = next_char
            self._accrued_input_without_formatting += next_char
        else:
            next_digit = unicode_digit(next_char, -1)
            if next_digit != -1:
                normalized_char = unicod(next_digit)
            else:  # pragma no cover
                normalized_char = next_char
            self._accrued_input_without_formatting += normalized_char
            self._national_number += normalized_char
        if remember_position:
            self._position_to_remember = len(self._accrued_input_without_formatting)
        return normalized_char

    def _input_digit_helper(self, next_char):
        # Note that formattingTemplate is not guaranteed to have a value, it
        # could be empty, e.g. when the next digit is entered after extracting
        # an IDD or NDD.
        digit_match = _DIGIT_PATTERN.search(self._formatting_template, self._last_match_position)
        if digit_match:
            # Reset to search for _DIGIT_PLACEHOLDER from start of string
            digit_match = _DIGIT_PATTERN.search(self._formatting_template)
            temp_template = re.sub(_DIGIT_PATTERN,
                                   next_char,
                                   self._formatting_template,
                                   count=1)
            self._formatting_template = temp_template + self._formatting_template[len(temp_template):]
            self._last_match_position = digit_match.start()
            return self._formatting_template[:self._last_match_position + 1]
        else:
            if len(self._possible_formats) == 1:
                # More digits are entered than we could handle, and there are
                # no other valid patterns to try.
                self._able_to_format = False
            # else, we just reset the formatting pattern.
            self._current_formatting_pattern = U_EMPTY_STRING
            return self._accrued_input
