"""Auto-generated file, do not edit by hand. MN metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_MN = PhoneMetadata(id='MN', country_code=976, international_prefix='001',
    general_desc=PhoneNumberDesc(national_number_pattern='[12]\\d{7,9}|[57-9]\\d{7}', possible_number_pattern='\\d{6,10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='[12](?:1\\d|2(?:[1-3]\\d?|7\\d)|3[2-8]\\d{1,2}|4[2-68]\\d{1,2}|5[1-4689]\\d{1,2})\\d{5}|5[0568]\\d{6}', possible_number_pattern='\\d{6,10}', example_number='50123456'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:8(?:[05689]\\d|3[01])|9[013-9]\\d)\\d{5}', possible_number_pattern='\\d{8}', example_number='88123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='7[05-8]\\d{6}', possible_number_pattern='\\d{8}', example_number='75123456'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='([12]\\d)(\\d{2})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['[12]1'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='([12]2\\d)(\\d{5,6})', format='\\1 \\2', leading_digits_pattern=['[12]2[1-3]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='([12]\\d{3})(\\d{5})', format='\\1 \\2', leading_digits_pattern=['[12](?:27|[3-5])', '[12](?:27|[3-5]\\d)2'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d{4})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[57-9]'], national_prefix_formatting_rule='\\1'),
        NumberFormat(pattern='([12]\\d{4})(\\d{4,5})', format='\\1 \\2', leading_digits_pattern=['[12](?:27|[3-5])', '[12](?:27|[3-5]\\d)[4-9]'], national_prefix_formatting_rule='0\\1')])
