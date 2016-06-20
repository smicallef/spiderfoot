"""Auto-generated file, do not edit by hand. ER metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_ER = PhoneMetadata(id='ER', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[12]\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:1[2-46]|2(?:4422|7799))|2(?:0(?:1(?:606|917)|2(?:099|914)))', possible_number_pattern='\\d{3,6}', example_number='113'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:1[2-6]|2(?:4422|7799))|2(?:0(?:1(?:606|917)|2(?:099|914)))', possible_number_pattern='\\d{3,6}', example_number='114'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
