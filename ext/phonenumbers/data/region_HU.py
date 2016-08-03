"""Auto-generated file, do not edit by hand. HU metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_HU = PhoneMetadata(id='HU', country_code=36, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[1-9]\\d{7,8}', possible_number_pattern='\\d{6,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:1\\d|2(?:1\\d|[2-9])|3(?:[2-7]|8\\d)|4[24-9]|5[2-79]|6[23689]|7(?:1\\d|[2-9])|8[2-57-9]|9[2-69])\\d{6}', possible_number_pattern='\\d{6,9}', example_number='12345678'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:[257]0|3[01])\\d{7}', possible_number_pattern='\\d{9}', example_number='201234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='80\\d{6}', possible_number_pattern='\\d{8}', example_number='80123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='9[01]\\d{6}', possible_number_pattern='\\d{8}', example_number='90123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='40\\d{6}', possible_number_pattern='\\d{8}', example_number='40123456'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='[48]0\\d{6}', possible_number_pattern='\\d{8}', example_number='80123456'),
    national_prefix='06',
    national_prefix_for_parsing='06',
    number_format=[NumberFormat(pattern='(1)(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['1'], national_prefix_formatting_rule='(\\1)'),
        NumberFormat(pattern='(\\d{2})(\\d{3})(\\d{3,4})', format='\\1 \\2 \\3', leading_digits_pattern=['[2-9]'], national_prefix_formatting_rule='(\\1)')],
    mobile_number_portable_region=True)
