"""Auto-generated file, do not edit by hand. TM metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_TM = PhoneMetadata(id='TM', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='0\\d', possible_number_pattern='\\d{2}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='0[1-3]', possible_number_pattern='\\d{2}', example_number='03'),
    short_code=PhoneNumberDesc(national_number_pattern='0[1-3]', possible_number_pattern='\\d{2}', example_number='03'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
