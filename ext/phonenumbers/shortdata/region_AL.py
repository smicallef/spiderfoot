"""Auto-generated file, do not edit by hand. AL metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_AL = PhoneMetadata(id='AL', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[15]\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:12|2[789])', possible_number_pattern='\\d{3}', example_number='129'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:1(?:2|6(?:000|1(?:06|11|23)))|2[5-9])|5\\d{4}', possible_number_pattern='\\d{3,6}', example_number='129'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
