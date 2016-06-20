"""Auto-generated file, do not edit by hand. AF metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_AF = PhoneMetadata(id='AF', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[14]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:02|19)', possible_number_pattern='\\d{3,5}', example_number='119'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:02|19)|40404', possible_number_pattern='\\d{3,5}', example_number='119'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='40404', possible_number_pattern='\\d{5}'),
    short_data=True)
