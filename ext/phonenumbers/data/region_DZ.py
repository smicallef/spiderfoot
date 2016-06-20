"""Auto-generated file, do not edit by hand. DZ metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_DZ = PhoneMetadata(id='DZ', country_code=213, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='(?:[1-4]|[5-9]\\d)\\d{7}', possible_number_pattern='\\d{8,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:1\\d|2[013-79]|3[0-8]|4[0135689])\\d{6}|9619\\d{5}', possible_number_pattern='\\d{8,9}', example_number='12345678'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:5[4-6]|7[7-9])\\d{7}|6(?:[569]\\d|7[0-6])\\d{6}', possible_number_pattern='\\d{9}', example_number='551234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{6}', possible_number_pattern='\\d{9}', example_number='800123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='80[3-689]1\\d{5}', possible_number_pattern='\\d{9}', example_number='808123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='80[12]1\\d{5}', possible_number_pattern='\\d{9}', example_number='801123456'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='98[23]\\d{6}', possible_number_pattern='\\d{9}', example_number='983123456'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='([1-4]\\d)(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['[1-4]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='([5-8]\\d{2})(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['[5-8]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(9\\d)(\\d{3})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['9'], national_prefix_formatting_rule='0\\1')])
