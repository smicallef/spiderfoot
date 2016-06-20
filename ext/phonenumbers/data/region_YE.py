"""Auto-generated file, do not edit by hand. YE metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_YE = PhoneMetadata(id='YE', country_code=967, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[1-7]\\d{6,8}', possible_number_pattern='\\d{6,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:1(?:7\\d|[2-68])|2[2-68]|3[2358]|4[2-58]|5[2-6]|6[3-58]|7[24-68])\\d{5}', possible_number_pattern='\\d{6,8}', example_number='1234567'),
    mobile=PhoneNumberDesc(national_number_pattern='7[0137]\\d{7}', possible_number_pattern='\\d{9}', example_number='712345678'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='([1-7])(\\d{3})(\\d{3,4})', format='\\1 \\2 \\3', leading_digits_pattern=['[1-6]|7[24-68]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(7\\d{2})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['7[0137]'], national_prefix_formatting_rule='0\\1')])
