"""Auto-generated file, do not edit by hand. 870 metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_870 = PhoneMetadata(id='001', country_code=870, international_prefix=None,
    general_desc=PhoneNumberDesc(national_number_pattern='[35-7]\\d{8}', possible_number_pattern='\\d{9}', example_number='301234567'),
    fixed_line=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA', example_number='301234567'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:[356]\\d|7[6-8])\\d{7}', possible_number_pattern='\\d{9}', example_number='301234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{3})', format='\\1 \\2 \\3')])
