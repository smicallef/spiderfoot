"""Auto-generated file, do not edit by hand. KP metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_KP = PhoneMetadata(id='KP', country_code=850, international_prefix='00|99',
    general_desc=PhoneNumberDesc(national_number_pattern='1\\d{9}|[28]\\d{7}', possible_number_pattern='\\d{6,8}|\\d{10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2\\d{7}|85\\d{6}', possible_number_pattern='\\d{6,8}', example_number='21234567'),
    mobile=PhoneNumberDesc(national_number_pattern='19[123]\\d{7}', possible_number_pattern='\\d{10}', example_number='1921234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='2(?:[0-24-9]\\d{2}|3(?:[0-79]\\d|8[02-9]))\\d{4}', possible_number_pattern='\\d{8}', example_number='23821234'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['1'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d)(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['2'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d{2})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['8'], national_prefix_formatting_rule='0\\1')])
