"""Auto-generated file, do not edit by hand. NP metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_NP = PhoneMetadata(id='NP', country_code=977, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[1-8]\\d{7}|9(?:[1-69]\\d{6,8}|7[2-6]\\d{5,7}|8\\d{8})', possible_number_pattern='\\d{6,10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:1[0-6]\\d|2[13-79][2-6]|3[135-8][2-6]|4[146-9][2-6]|5[135-7][2-6]|6[13-9][2-6]|7[15-9][2-6]|8[1-46-9][2-6]|9[1-79][2-6])\\d{5}', possible_number_pattern='\\d{6,8}', example_number='14567890'),
    mobile=PhoneNumberDesc(national_number_pattern='9(?:6[013]|7[245]|8[0-24-6])\\d{7}', possible_number_pattern='\\d{10}', example_number='9841234567'),
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
    number_format=[NumberFormat(pattern='(1)(\\d{7})', format='\\1-\\2', leading_digits_pattern=['1[2-6]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d{2})(\\d{6})', format='\\1-\\2', leading_digits_pattern=['1[01]|[2-8]|9(?:[1-69]|7[15-9])'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(9\\d{2})(\\d{7})', format='\\1-\\2', leading_digits_pattern=['9(?:6[013]|7[245]|8)'], national_prefix_formatting_rule='\\1')])
