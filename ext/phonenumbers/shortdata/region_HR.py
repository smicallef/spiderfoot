"""Auto-generated file, do not edit by hand. HR metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_HR = PhoneMetadata(id='HR', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[19]\\d{1,5}', possible_number_pattern='\\d{2,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='116(?:00[06]|111)', possible_number_pattern='\\d{6}', example_number='116000'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:12|9[2-4])|9[34]', possible_number_pattern='\\d{2,6}', example_number='112'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:1[28]|16\\d{3}|987|9[2-5])|9[34]', possible_number_pattern='\\d{2,6}', example_number='112'),
    standard_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
