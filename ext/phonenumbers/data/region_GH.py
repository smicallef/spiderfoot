"""Auto-generated file, do not edit by hand. GH metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_GH = PhoneMetadata(id='GH', country_code=233, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[235]\\d{8}|8\\d{7}', possible_number_pattern='\\d{7,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='3(?:0[237]\\d|[167](?:2[0-6]|7\\d)|2(?:2[0-5]|7\\d)|3(?:2[0-3]|7\\d)|4(?:2[013-9]|3[01]|7\\d)|5(?:2[0-7]|7\\d)|8(?:2[0-2]|7\\d)|9(?:20|7\\d))\\d{5}', possible_number_pattern='\\d{7,9}', example_number='302345678'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:2[034678]\\d|5(?:[047]\\d|5[3-6]|6[01]))\\d{6}', possible_number_pattern='\\d{9}', example_number='231234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{5}', possible_number_pattern='\\d{8}', example_number='80012345'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='800\\d{5}', possible_number_pattern='\\d{8}', example_number='80012345'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['[235]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d{3})(\\d{5})', format='\\1 \\2', leading_digits_pattern=['8'], national_prefix_formatting_rule='0\\1')],
    mobile_number_portable_region=True)
