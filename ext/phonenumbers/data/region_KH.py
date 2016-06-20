"""Auto-generated file, do not edit by hand. KH metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_KH = PhoneMetadata(id='KH', country_code=855, international_prefix='00[14-9]',
    general_desc=PhoneNumberDesc(national_number_pattern='[1-9]\\d{7,9}', possible_number_pattern='\\d{6,10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:2[3-6]|3[2-6]|4[2-4]|[5-7][2-5])(?:[237-9]|4[56]|5\\d|6\\d?)\\d{5}|23(?:4[234]|8\\d{2})\\d{4}', possible_number_pattern='\\d{6,9}', example_number='23756789'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:1(?:[013-79]\\d|[28]\\d{1,2})|2[3-6]48|3(?:[18]\\d{2}|[2-6]48)|4[2-4]48|5[2-5]48|6(?:[016-9]\\d|[2-5]48)|7(?:[07-9]\\d|[16]\\d{2}|[2-5]48)|8(?:[013-79]\\d|8\\d{2})|9(?:6\\d{2}|7\\d{1,2}|[0-589]\\d))\\d{5}', possible_number_pattern='\\d{8,9}', example_number='91234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='1800(?:1\\d|2[019])\\d{4}', possible_number_pattern='\\d{10}', example_number='1800123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='1900(?:1\\d|2[09])\\d{4}', possible_number_pattern='\\d{10}', example_number='1900123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{3})(\\d{3,4})', format='\\1 \\2 \\3', leading_digits_pattern=['1\\d[1-9]|[2-9]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(1[89]00)(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['1[89]0'])])
