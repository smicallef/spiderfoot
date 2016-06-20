"""Auto-generated file, do not edit by hand. NL metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_NL = PhoneMetadata(id='NL', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[19]\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='116(?:00[06]|123)', possible_number_pattern='\\d{6}', example_number='116000'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='112|911', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:1(?:2|6(?:00[06]|123))|833)|911', possible_number_pattern='\\d{3,6}', example_number='1833'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
