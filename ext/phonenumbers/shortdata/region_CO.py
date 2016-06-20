"""Auto-generated file, do not edit by hand. CO metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_CO = PhoneMetadata(id='CO', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[148]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:1[29]|23|32|56)', possible_number_pattern='\\d{3}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:06|1[2569]|2[357]|3[27]|4[467]|5[36]|6[45]|95)|40404|85432', possible_number_pattern='\\d{3,5}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='40404|85432', possible_number_pattern='\\d{5}'),
    short_data=True)
