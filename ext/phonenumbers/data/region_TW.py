"""Auto-generated file, do not edit by hand. TW metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_TW = PhoneMetadata(id='TW', country_code=886, international_prefix='0(?:0[25679]|19)',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-689]\\d{7,8}|7\\d{7,9}', possible_number_pattern='\\d{8,10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='[2-8]\\d{7,8}', possible_number_pattern='\\d{8,9}', example_number='21234567'),
    mobile=PhoneNumberDesc(national_number_pattern='9\\d{8}', possible_number_pattern='\\d{9}', example_number='912345678'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{6}', possible_number_pattern='\\d{9}', example_number='800123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='900\\d{6}', possible_number_pattern='\\d{9}', example_number='900123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='70\\d{8}', possible_number_pattern='\\d{10}', example_number='7012345678'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    preferred_extn_prefix='#',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='([2-8])(\\d{3,4})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['[2-6]|[78][1-9]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='([89]\\d{2})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['80|9'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(70)(\\d{4})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['70'], national_prefix_formatting_rule='0\\1')],
    mobile_number_portable_region=True)
