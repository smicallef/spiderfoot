"""Auto-generated file, do not edit by hand. EG metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_EG = PhoneMetadata(id='EG', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[13]\\d{2,4}', possible_number_pattern='\\d{3,5}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:2[23]|80)', possible_number_pattern='\\d{3}', example_number='122'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:2[23]|80)|34400', possible_number_pattern='\\d{3,5}', example_number='122'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='34400', possible_number_pattern='\\d{5}', example_number='34400'),
    short_data=True)
