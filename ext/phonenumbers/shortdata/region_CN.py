"""Auto-generated file, do not edit by hand. CN metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_CN = PhoneMetadata(id='CN', country_code=None, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[19]\\d{2,5}', possible_number_pattern='\\d{3,6}'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    emergency=PhoneNumberDesc(national_number_pattern='1(?:1[09]|20)', possible_number_pattern='\\d{3}', example_number='119'),
    short_code=PhoneNumberDesc(national_number_pattern='1(?:00\\d{2}|1[09]|20)|95\\d{3,4}', possible_number_pattern='\\d{3,6}', example_number='119'),
    standard_rate=PhoneNumberDesc(national_number_pattern='100\\d{2}|95\\d{3,4}', possible_number_pattern='\\d{5,6}', example_number='95566'),
    carrier_specific=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    short_data=True)
