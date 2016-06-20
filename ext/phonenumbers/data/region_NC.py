"""Auto-generated file, do not edit by hand. NC metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_NC = PhoneMetadata(id='NC', country_code=687, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-57-9]\\d{5}', possible_number_pattern='\\d{6}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:2[03-9]|3[0-5]|4[1-7]|88)\\d{4}', possible_number_pattern='\\d{6}', example_number='201234'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:5[0-4]|[79]\\d|8[0-79])\\d{4}', possible_number_pattern='\\d{6}', example_number='751234'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='36\\d{4}', possible_number_pattern='\\d{6}', example_number='366711'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{2})(\\d{2})', format='\\1.\\2.\\3', leading_digits_pattern=['[2-46-9]|5[0-4]'])])
