"""Auto-generated file, do not edit by hand. AZ metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_AZ = PhoneMetadata(id='AZ', country_code=994, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[1-9]\\d{8}', possible_number_pattern='\\d{7,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:1[28]\\d|2(?:02|1[24]|2[2-4]|33|[45]2|6[23])|365)\\d{6}', possible_number_pattern='\\d{7,9}', example_number='123123456'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:4[04]|5[015]|60|7[07])\\d{7}', possible_number_pattern='\\d{9}', example_number='401234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='88\\d{7}', possible_number_pattern='\\d{9}', example_number='881234567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='900200\\d{3}', possible_number_pattern='\\d{9}', example_number='900200123'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{3})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['(?:1[28]|2(?:[45]2|[0-36])|365)'], national_prefix_formatting_rule='(0\\1)'),
        NumberFormat(pattern='(\\d{2})(\\d{3})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['[4-8]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d{3})(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['9'], national_prefix_formatting_rule='0\\1')],
    mobile_number_portable_region=True)
