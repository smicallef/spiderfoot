"""Auto-generated file, do not edit by hand. MX metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_MX = PhoneMetadata(id='MX', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[0579]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='53053|7766', possible_number_pattern='\\d{4,5}', example_number='7766'),
    emergency=PhoneNumberDesc(national_number_pattern='0(?:6[0568]|80)|911', possible_number_pattern='\\d{3}', example_number='066'),
    short_code=PhoneNumberDesc(national_number_pattern='0(?:[249]0|3[01]|5[015]|6[01568]|7[0-578]|8[089])|53053|7766|911', possible_number_pattern='\\d{3,5}', example_number='030'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
