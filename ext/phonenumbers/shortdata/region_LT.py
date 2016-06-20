"""Auto-generated file, do not edit by hand. LT metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_LT = PhoneMetadata(id='LT', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[01]\\d{1,5}', possible_number_pattern='\\d{2,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='116(?:000|1(?:11|23))', possible_number_pattern='\\d{6}', example_number='116000'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='0(?:11?|22?|33?)|1(?:0[123]|12)', possible_number_pattern='\\d{2,6}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='0(?:11?|22?|33?)|1(?:0[123]|1(?:2|6(?:000|1(?:11|23))))', possible_number_pattern='\\d{2,6}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
