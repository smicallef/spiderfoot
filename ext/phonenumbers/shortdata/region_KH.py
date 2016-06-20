"""Auto-generated file, do not edit by hand. KH metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_KH = PhoneMetadata(id='KH', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[146]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='11[789]|666', possible_number_pattern='\\d{3}', example_number='117'),
    short_code=PhoneNumberDesc(national_number_pattern='11[789]|40404|666', possible_number_pattern='\\d{3,5}', example_number='117'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='40404', possible_number_pattern='\\d{5}'),
    short_data=True)
