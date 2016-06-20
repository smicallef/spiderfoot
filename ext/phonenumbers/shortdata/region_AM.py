"""Auto-generated file, do not edit by hand. AM metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_AM = PhoneMetadata(id='AM', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[148]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='10[123]', possible_number_pattern='\\d{3}', example_number='102'),
    short_code=PhoneNumberDesc(national_number_pattern='1\\d{2}|40404|8[1-7]\\d{2}', possible_number_pattern='\\d{3,5}', example_number='8711'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='40404', possible_number_pattern='\\d{5}'),
    short_data=True)
