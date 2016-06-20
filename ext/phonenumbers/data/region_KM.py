"""Auto-generated file, do not edit by hand. KM metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_KM = PhoneMetadata(id='KM', country_code=269, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[379]\\d{6}', possible_number_pattern='\\d{7}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='7(?:6[0-37-9]|7[0-57-9])\\d{4}', possible_number_pattern='\\d{7}', example_number='7712345'),
    mobile=PhoneNumberDesc(national_number_pattern='3[234]\\d{5}', possible_number_pattern='\\d{7}', example_number='3212345'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='(?:39[01]|9[01]0)\\d{4}', possible_number_pattern='\\d{7}', example_number='9001234'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{2})(\\d{2})', format='\\1 \\2 \\3')])
