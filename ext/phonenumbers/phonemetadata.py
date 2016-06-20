"""PhoneMetadata object definitions"""

# Based on original Java code and protocol buffer:
#     resources/phonemetadata.proto
#     java/src/com/google/i18n/phonenumbers/Phonemetadata.java
#   Copyright (C) 2010-2011 The Libphonenumber Authors
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
from .util import UnicodeMixin, ImmutableMixin, mutating_method
from .util import u, unicod, rpr, force_unicode

REGION_CODE_FOR_NON_GEO_ENTITY = u("001")


class NumberFormat(UnicodeMixin, ImmutableMixin):
    """Representation of way that a phone number can be formatted for output"""
    @mutating_method
    def __init__(self,
                 pattern=None,
                 format=None,
                 leading_digits_pattern=None,
                 national_prefix_formatting_rule=None,
                 national_prefix_optional_when_formatting=False,
                 domestic_carrier_code_formatting_rule=None):
        # pattern is a regex that is used to match the national (significant)
        # number. For example, the pattern "(20)(\d{4})(\d{4})" will match
        # number "2070313000", which is the national (significant) number for
        # Google London. Note the presence of the parentheses, which are
        # capturing groups what specifies the grouping of numbers.
        self.pattern = force_unicode(pattern)  # Unicode string holding regexp

        # format specifies how the national (significant) number matched by
        # pattern should be formatted. Using the same example as above, format
        # could contain "$1 $2 $3", meaning that the number should be
        # formatted as "20 7031 3000". Each $x is replaced by the numbers
        # captured by group x in the regex specified by pattern.
        self.format = force_unicode(format)  # None or Unicode string

        # This field is a regex that is used to match a certain number of
        # digits at the beginning of the national (significant) number. When
        # the match is successful, the accompanying pattern and format should
        # be used to format this number. For example, if
        # leading_digits="[1-3]|44", then all the national numbers starting
        # with 1, 2, 3 or 44 should be formatted using the accompanying
        # pattern and format.
        #
        # The first leading_digits_pattern matches up to the first three digits
        # of the national (significant) number; the next one matches the first
        # four digits, then the first five and so on, until the
        # leading_digits_pattern can uniquely identify one pattern and format
        # to be used to format the number.
        #
        # In the case when only one formatting pattern exists, no
        # leading_digits_pattern is needed.
        self.leading_digits_pattern = []  # list of Unicode strings holding regexps
        if leading_digits_pattern is not None:
            self.leading_digits_pattern = [force_unicode(p) for p in leading_digits_pattern]

        # This field specifies how the national prefix ($NP) together with the
        # first group ($FG) in the national significant number should be
        # formatted in the NATIONAL format when a national prefix exists for a
        # certain country. For example, when this field contains "($NP$FG)", a
        # number from Beijing, China (whose $NP = 0), which would by default
        # be formatted without national prefix as 10 1234 5678 in NATIONAL
        # format, will instead be formatted as (010) 1234 5678; to format it
        # as (0)10 1234 5678, the field would contain "($NP)$FG". Note $FG
        # should always be present in this field, but $NP can be omitted. For
        # example, having "$FG" could indicate the number should be formatted
        # in NATIONAL format without the national prefix. This is commonly
        # used to override the rule specified for the territory in the XML
        # file.
        #
        # When this field is missing, a number will be formatted without
        # national prefix in NATIONAL format. This field does not affect how a
        # number is formatted in other formats, such as INTERNATIONAL.
        self.national_prefix_formatting_rule = force_unicode(national_prefix_formatting_rule)  # None or Unicode string

        # This field specifies whether the $NP can be omitted when formatting
        # a number in national format, even though it usually wouldn't be. For
        # example, a UK number would be formatted by our library as 020 XXXX
        # XXXX. If we have commonly seen this number written by people without
        # the leading 0, for example as (20) XXXX XXXX, this field would be
        # set to true. This will be inherited from the value set for the
        # territory in the XML file, unless a national_prefix_formatting_rule
        # is defined specifically for this NumberFormat.
        self.national_prefix_optional_when_formatting = bool(national_prefix_optional_when_formatting)

        # This field specifies how any carrier code ($CC) together with the
        # first group ($FG) in the national significant number should be
        # formatted when format_with_carrier_code is called, if carrier codes
        # are used for a certain country.
        self.domestic_carrier_code_formatting_rule = force_unicode(domestic_carrier_code_formatting_rule)  # None or Unicode string

    def merge_from(self, other):
        """Merge information from another NumberFormat object into this one."""
        if other.pattern is not None:
            self.pattern = other.pattern
        if other.format is not None:
            self.format = other.format
        self.leading_digits_pattern.extend(other.leading_digits_pattern)
        if other.national_prefix_formatting_rule is not None:
            self.national_prefix_formatting_rule = other.national_prefix_formatting_rule
        self.national_prefix_optional_when_formatting = other.national_prefix_optional_when_formatting
        if other.domestic_carrier_code_formatting_rule is not None:
            self.domestic_carrier_code_formatting_rule = other.domestic_carrier_code_formatting_rule

    def __eq__(self, other):
        if not isinstance(other, NumberFormat):
            return False
        return (repr(self) == repr(other))

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return str(self)

    def __unicode__(self):
        # Generate a string that is valid Python input for the constructor.
        # Note that we use rpr (variant of repr), which generates its own quotes.
        result = unicod("NumberFormat(pattern=%s, format=%s") % (rpr(self.pattern), rpr(self.format))
        if len(self.leading_digits_pattern) > 0:
            result += (unicod(", leading_digits_pattern=[%s]") %
                       unicod(", ").join([rpr(ld) for ld in self.leading_digits_pattern]))
        if self.national_prefix_formatting_rule is not None:
            result += unicod(", national_prefix_formatting_rule=%s") % rpr(self.national_prefix_formatting_rule)
        if self.national_prefix_optional_when_formatting:
            result += unicod(", national_prefix_optional_when_formatting=%s") % str(self.national_prefix_optional_when_formatting)
        if self.domestic_carrier_code_formatting_rule is not None:
            result += unicod(", domestic_carrier_code_formatting_rule=%s") % rpr(self.domestic_carrier_code_formatting_rule)
        result += unicod(")")
        return result


class PhoneNumberDesc(UnicodeMixin, ImmutableMixin):
    """Class representing the description of a set of phone numbers."""
    @mutating_method
    def __init__(self,
                 national_number_pattern=None,
                 possible_number_pattern=None,
                 example_number=None):
        # The national_number_pattern is the pattern that a valid national
        # significant number would match. This specifies information such as
        # its total length and leading digits.
        self.national_number_pattern = force_unicode(national_number_pattern)  # None or Unicode string holding regexp

        # The possible_number_pattern represents what a potentially valid
        # phone number for this region may be written as. This is a superset
        # of the national_number_pattern above and includes numbers that have
        # the area code omitted. Typically the only restrictions here are in
        # the number of digits.  This could be used to highlight tokens in a
        # text that may be a phone number, or to quickly prune numbers that
        # could not possibly be a phone number for this locale.
        self.possible_number_pattern = force_unicode(possible_number_pattern)  # None or Unicode string holding regexp

        # An example national significant number for the specific type. It
        # should not contain any formatting information.
        self.example_number = force_unicode(example_number)  # None or Unicode string

    def merge_from(self, other):
        """Merge information from another PhoneNumberDesc object into this one."""
        if other.national_number_pattern is not None:
            self.national_number_pattern = other.national_number_pattern
        if other.possible_number_pattern is not None:
            self.possible_number_pattern = other.possible_number_pattern
        if other.example_number is not None:
            self.example_number = other.example_number

    def __eq__(self, other):
        if not isinstance(other, PhoneNumberDesc):
            return False
        return (repr(self) == repr(other))

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return str(self)

    def __unicode__(self):
        # Generate a string that is valid Python input for constructor
        result = unicod("PhoneNumberDesc(")
        sep = unicod("")
        if self.national_number_pattern is not None:
            result += unicod("%snational_number_pattern=%s") % (sep, rpr(self.national_number_pattern))
            sep = unicod(", ")
        if self.possible_number_pattern is not None:
            result += unicod("%spossible_number_pattern=%s") % (sep, rpr(self.possible_number_pattern))
            sep = unicod(", ")
        if self.example_number is not None:
            result += unicod("%sexample_number=%s") % (sep, rpr(self.example_number))
            sep = unicod(", ")
        result += unicod(")")
        return result


class PhoneMetadata(UnicodeMixin, ImmutableMixin):
    """Class representing metadata for international telephone numbers for a region.

    This class is hand created based on phonemetadata.proto. Please refer to that file
    for detailed descriptions of the meaning of each field.
    """
    # If a region code is a key in this dict, metadata for that region is available.
    # The corresponding value of the map is either:
    #   - a function which loads the region's metadata
    #   - None, to indicate that the metadata is already loaded
    _region_available = {}  # ISO 3166-1 alpha 2 => function or None
    # Likewise for short number metadata.
    _short_region_available = {}  # ISO 3166-1 alpha 2 => function or None
    # Likewise for non-geo country calling codes.
    _country_code_available = {}  # country calling code (as int) => function or None

    _region_metadata = {}  # ISO 3166-1 alpha 2 => PhoneMetadata
    _short_region_metadata = {}  # ISO 3166-1 alpha 2 => PhoneMetadata
    # A mapping from a country calling code for a non-geographical entity to
    # the PhoneMetadata for that country calling code. Examples of the country
    # calling codes include 800 (International Toll Free Service) and 808
    # (International Shared Cost Service).
    _country_code_metadata = {}  # country calling code (as int) => PhoneMetadata

    @classmethod
    def metadata_for_region(kls, region_code, default=None):
        loader = kls._region_available.get(region_code, None)
        if loader is not None:
            # Region metadata is available but has not yet been loaded.  Do so now.
            loader(region_code)
            kls._region_available[region_code] = None
        return kls._region_metadata.get(region_code, default)

    @classmethod
    def short_metadata_for_region(kls, region_code, default=None):
        loader = kls._short_region_available.get(region_code, None)
        if loader is not None:
            # Region short number metadata is available but has not yet been loaded.  Do so now.
            loader(region_code)
            kls._short_region_available[region_code] = None
        return kls._short_region_metadata.get(region_code, default)

    @classmethod
    def metadata_for_nongeo_region(kls, country_code, default=None):
        loader = kls._country_code_available.get(country_code, None)
        if loader is not None:
            # Region metadata is available but has not yet been loaded.  Do so now.
            loader(country_code)
            kls._country_code_available[country_code] = None
        return kls._country_code_metadata.get(country_code, default)

    @classmethod
    def metadata_for_region_or_calling_code(kls, country_calling_code, region_code):
        if region_code == REGION_CODE_FOR_NON_GEO_ENTITY:
            return kls.metadata_for_nongeo_region(country_calling_code, None)
        else:
            return kls.metadata_for_region(region_code, None)

    @classmethod
    def register_region_loader(kls, region_code, loader):
        kls._region_available[region_code] = loader

    @classmethod
    def register_short_region_loader(kls, region_code, loader):
        kls._short_region_available[region_code] = loader

    @classmethod
    def register_nongeo_region_loader(kls, country_code, loader):
        kls._country_code_available[country_code] = loader

    @classmethod
    def load_all(kls):
        """Force immediate load of all metadata"""
        # Force expansion of contents to lists because we invalidate the iterator
        for region_code, loader in list(kls._region_available.items()):
            if loader is not None:  # pragma no cover
                loader(region_code)
                kls._region_available[region_code] = None
        for country_code, loader in list(kls._country_code_available.items()):
            if loader is not None:
                loader(country_code)
                kls._country_code_available[region_code] = None

    @mutating_method
    def __init__(self,
                 id,
                 general_desc=None,
                 fixed_line=None,
                 mobile=None,
                 toll_free=None,
                 premium_rate=None,
                 shared_cost=None,
                 personal_number=None,
                 voip=None,
                 pager=None,
                 uan=None,
                 emergency=None,
                 voicemail=None,
                 short_code=None,
                 standard_rate=None,
                 carrier_specific=None,
                 no_international_dialling=None,
                 country_code=None,
                 international_prefix=None,
                 preferred_international_prefix=None,
                 national_prefix=None,
                 preferred_extn_prefix=None,
                 national_prefix_for_parsing=None,
                 national_prefix_transform_rule=None,
                 number_format=None,
                 intl_number_format=None,
                 main_country_for_code=False,
                 leading_digits=None,
                 leading_zero_possible=False,
                 mobile_number_portable_region=False,
                 short_data=False,
                 register=True):
        # The general_desc contains information which is a superset of
        # descriptions for all types of phone numbers. If any element is
        # missing in the description of a specific type of number, the element
        # will inherit from its counterpart in the general_desc. Every locale
        # is assumed to have fixed line and mobile numbers - if these types
        # are missing altogether, they will inherit all fields from the
        # general_desc. For all other types, if the whole type is missing and
        # it is relevant for the metadata, it will be given a
        # national_number_pattern of "NA" and a possible_number_pattern of
        # "NA".
        self.general_desc = general_desc  # None or PhoneNumberDesc
        self.fixed_line = fixed_line  # None or PhoneNumberDesc
        self.mobile = mobile  # None or PhoneNumberDesc
        self.toll_free = toll_free  # None or PhoneNumberDesc
        self.premium_rate = premium_rate  # None or PhoneNumberDesc
        self.shared_cost = shared_cost  # None or PhoneNumberDesc
        self.personal_number = personal_number  # None or PhoneNumberDesc
        self.voip = voip  # None or PhoneNumberDesc
        self.pager = pager  # None or PhoneNumberDesc
        self.uan = uan  # None or PhoneNumberDesc
        self.emergency = emergency  # None or PhoneNumberDesc
        self.voicemail = voicemail  # None or PhoneNumberDesc
        self.short_code = short_code  # None or PhoneNumberDesc
        self.standard_rate = standard_rate  # None or PhoneNumberDesc
        self.carrier_specific = carrier_specific  # None or PhoneNumberDesc

        # The rules here distinguish the numbers that are only able to be
        # dialled nationally.
        self.no_international_dialling = no_international_dialling  # None or PhoneNumberDesc

        # The ISO 3166-1 alpha-2 representation of a country/region, with the
        # exception of "country calling codes" used for non-geographical
        # entities, such as Universal International Toll Free Number
        # (+800). These are all given the ID "001", since this is the numeric
        # region code for the world according to UN M.49:
        # http://en.wikipedia.org/wiki/UN_M.49
        self.id = force_unicode(id)  # None or Unicode string

        # The country calling code that one would dial from overseas when
        # trying to dial a phone number in this country. For example, this
        # would be "64" for New Zealand.
        self.country_code = country_code  # None or int

        # The international_prefix of country A is the number that needs to be
        # dialled from country A to another country (country B). This is
        # followed by the country code for country B. Note that some countries
        # may have more than one international prefix, and for those cases, a
        # regular expression matching the international prefixes will be
        # stored in this field.
        self.international_prefix = force_unicode(international_prefix)  # None or Unicode string

        # If more than one international prefix is present, a preferred prefix
        # can be specified here for out-of-country formatting purposes. If
        # this field is not present, and multiple international prefixes are
        # present, then "+" will be used instead.
        self.preferred_international_prefix = force_unicode(preferred_international_prefix)  # None or Unicode string

        # The national prefix of country A is the number that needs to be
        # dialled before the national significant number when dialling
        # internally. This would not be dialled when dialling
        # internationally. For example, in New Zealand, the number that would
        # be locally dialled as 09 345 3456 would be dialled from overseas as
        # +64 9 345 3456. In this case, 0 is the national prefix.
        self.national_prefix = force_unicode(national_prefix)  # None or Unicode string

        # The preferred prefix when specifying an extension in this
        # country. This is used for formatting only, and if this is not
        # specified, a suitable default should be used instead. For example,
        # if you wanted extensions to be formatted in the following way: 1
        # (365) 345 445 ext. 2345 " ext. "  should be the preferred extension
        # prefix.
        self.preferred_extn_prefix = force_unicode(preferred_extn_prefix)  # None or Unicode string

        # This field is used for cases where the national prefix of a country
        # contains a carrier selection code, and is written in the form of a
        # regular expression. For example, to dial the number 2222-2222 in
        # Fortaleza, Brazil (area code 85) using the long distance carrier Oi
        # (selection code 31), one would dial 0 31 85 2222 2222. Assuming the
        # only other possible carrier selection code is 32, the field will
        # contain "03[12]".
        #
        # When it is missing, this field inherits the value of national_prefix,
        # if that is present.
        self.national_prefix_for_parsing = force_unicode(national_prefix_for_parsing)  # None or Unicode string holding regexp

        # This field is only populated and used under very rare situations.
        # For example, mobile numbers in Argentina are written in two
        # completely different ways when dialed in-country and out-of-country
        # (e.g. 0343 15 555 1212 is exactly the same number as +54 9 343 555
        # 1212).  This field is used together with national_prefix_for_parsing
        # to transform the number into a particular representation for storing
        # in the PhoneNumber class in those rare cases.
        self.national_prefix_transform_rule = force_unicode(national_prefix_transform_rule)  # None or Unicode string

        # Specifies whether the mobile and fixed-line patterns are the same or
        # not.  This is used to speed up determining phone number type in
        # countries where these two types of phone numbers can never be
        # distinguished.
        self.same_mobile_and_fixed_line_pattern = (self.mobile == self.fixed_line)

        # Note that the number format here is used for formatting only, not
        # parsing.  Hence all the varied ways a user *may* write a number need
        # not be recorded - just the ideal way we would like to format it for
        # them. When this element is absent, the national significant number
        # will be formatted as a whole without any formatting applied.
        self.number_format = []  # List of NumberFormat objects
        if number_format is not None:
            self.number_format = number_format

        # This field is populated only when the national significant number is
        # formatted differently when it forms part of the INTERNATIONAL format
        # and NATIONAL format. A case in point is mobile numbers in Argentina:
        # The number, which would be written in INTERNATIONAL format as
        # +54 9 343 555 1212, will be written as 0343 15 555 1212 for NATIONAL
        # format. In this case, the prefix 9 is inserted when dialling from
        # overseas, but otherwise the prefix 0 and the carrier selection code
        # 15 (inserted after the area code of 343) is used.
        # Note: this field is populated by setting a value for <intlFormat>
        # inside the <numberFormat> tag in the XML file. If <intlFormat> is
        # not set then it defaults to the same value as the <format> tag.
        #
        # Examples:
        #   To set the <intlFormat> to a different value than the <format>:
        #     <numberFormat pattern=....>
        #       <format>$1 $2 $3</format>
        #       <intlFormat>$1-$2-$3</intlFormat>
        #     </numberFormat>
        #
        #   To have a format only used for national formatting, set <intlFormat> to
        #   "NA":
        #     <numberFormat pattern=....>
        #       <format>$1 $2 $3</format>
        #       <intlFormat>NA</intlFormat>
        #     </numberFormat>
        self.intl_number_format = []  # List of NumberFormat objects
        if intl_number_format is not None:
            self.intl_number_format = intl_number_format

        # This field is set when this country is considered to be the main
        # country for a calling code. It may not be set by more than one
        # country with the same calling code, and it should not be set by
        # countries with a unique calling code. This can be used to indicate
        # that "GB" is the main country for the calling code "44" for example,
        # rather than Jersey or the Isle of Man.
        self.main_country_for_code = bool(main_country_for_code)

        # This field is populated only for countries or regions that share a
        # country calling code. If a number matches this pattern, it could
        # belong to this region. This is not intended as a replacement for
        # is_valid_for_region, and does not mean the number must come from this
        # region (for example, 800 numbers are valid for all NANPA countries.)
        # This field should be a regular expression of the expected prefix
        # match.
        self.leading_digits = force_unicode(leading_digits)  # None or Unicode string holding regexp

        # The leading zero in a phone number is meaningful in some countries
        # (e.g.  Italy). This means they cannot be dropped from the national
        # number when converting into international format. If leading zeros
        # are possible for valid international numbers for this region/country
        # then set this to true.  This only needs to be set for the region
        # that is the main_country_for_code and all regions associated with
        # that calling code will use the same setting.
        self.leading_zero_possible = bool(leading_zero_possible)

        # This field is set when this country has implemented mobile number
        # portability. This means that transferring mobile numbers between
        # carriers is allowed. A consequence of this is that phone prefix to
        # carrier mapping is less reliable.
        self.mobile_number_portable_region = mobile_number_portable_region  # bool

        # Record whether this metadata is for short numbers or normal numbers.
        self.short_data = short_data  # bool

        if register:
            # Register this instance with the relevant class-wide map
            if self.id == REGION_CODE_FOR_NON_GEO_ENTITY:
                kls_map = PhoneMetadata._country_code_metadata
                id = self.country_code
            elif self.short_data:
                kls_map = PhoneMetadata._short_region_metadata
                id = self.id
            else:
                kls_map = PhoneMetadata._region_metadata
                id = self.id
            if id in kls_map:
                other = kls_map[id]
                if self != other:
                    raise Exception("Duplicate PhoneMetadata for %s (from %s:%s)" % (id, self.id, self.country_code))
            else:
                kls_map[id] = self

    def __eq__(self, other):
        if not isinstance(other, PhoneMetadata):
            return False
        return (repr(self) == repr(other))

    def __ne__(self, other):
        return not self.__eq__(other)

    def __repr__(self):
        return str(self)

    def __unicode__(self):
        # Generate a string that is valid Python input for the constructor
        result = (unicod("PhoneMetadata(id='%s', country_code=%r, international_prefix=%s") %
                  (self.id, self.country_code, rpr(self.international_prefix)))
        result += unicod(",\n    general_desc=%s") % self.general_desc
        if self.fixed_line is not None:
            result += unicod(",\n    fixed_line=%s") % self.fixed_line
        if self.mobile is not None:
            result += unicod(",\n    mobile=%s") % self.mobile
        if self.toll_free is not None:
            result += unicod(",\n    toll_free=%s") % self.toll_free
        if self.premium_rate is not None:
            result += unicod(",\n    premium_rate=%s") % self.premium_rate
        if self.shared_cost is not None:
            result += unicod(",\n    shared_cost=%s") % self.shared_cost
        if self.personal_number is not None:
            result += unicod(",\n    personal_number=%s") % self.personal_number
        if self.voip is not None:
            result += unicod(",\n    voip=%s") % self.voip
        if self.pager is not None:
            result += unicod(",\n    pager=%s") % self.pager
        if self.uan is not None:
            result += unicod(",\n    uan=%s") % self.uan
        if self.emergency is not None:
            result += unicod(",\n    emergency=%s") % self.emergency
        if self.voicemail is not None:
            result += unicod(",\n    voicemail=%s") % self.voicemail
        if self.short_code is not None:
            result += unicod(",\n    short_code=%s") % self.short_code
        if self.standard_rate is not None:
            result += unicod(",\n    standard_rate=%s") % self.standard_rate
        if self.carrier_specific is not None:
            result += unicod(",\n    carrier_specific=%s") % self.carrier_specific
        if self.no_international_dialling is not None:
            result += unicod(",\n    no_international_dialling=%s") % self.no_international_dialling

        if self.preferred_international_prefix is not None:
            result += unicod(",\n    preferred_international_prefix=%s") % rpr(self.preferred_international_prefix)
        if self.national_prefix is not None:
            result += unicod(",\n    national_prefix=%s") % rpr(self.national_prefix)
        if self.preferred_extn_prefix is not None:
            result += unicod(",\n    preferred_extn_prefix=%s") % rpr(self.preferred_extn_prefix)
        if self.national_prefix_for_parsing is not None:
            result += unicod(",\n    national_prefix_for_parsing=%s") % rpr(self.national_prefix_for_parsing)
        if self.national_prefix_transform_rule is not None:
            # Note that we use rpr() on self.national_prefix_transform_rule, which generates its own quotes
            result += unicod(",\n    national_prefix_transform_rule=%s") % rpr(self.national_prefix_transform_rule)
        if len(self.number_format) > 0:
            result += unicod(",\n    number_format=[%s]") % unicod(',\n        ').join(map(u, self.number_format))
        if len(self.intl_number_format) > 0:
            result += unicod(",\n    intl_number_format=[%s]") % unicod(',\n        ').join(map(u, self.intl_number_format))
        if self.main_country_for_code:
            result += unicod(",\n    main_country_for_code=True")
        if self.leading_digits is not None:
            result += unicod(",\n    leading_digits='%s'") % self.leading_digits
        if self.leading_zero_possible:
            result += unicod(",\n    leading_zero_possible=True")
        if self.mobile_number_portable_region:
            result += unicod(",\n    mobile_number_portable_region=True")
        if self.short_data:
            result += unicod(",\n    short_data=True")
        result += unicod(")")
        return result
