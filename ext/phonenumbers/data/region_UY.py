"""Auto-generated file, do not edit by hand. UY metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_UY = PhoneMetadata(id='UY', country_code=598, international_prefix='0(?:1[3-9]\\d|0)',
    general_desc=PhoneNumberDesc(national_number_pattern='[2489]\\d{6,7}', possible_number_pattern='\\d{7,8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2\\d{7}|4[2-7]\\d{6}', possible_number_pattern='\\d{7,8}', example_number='21231234'),
    mobile=PhoneNumberDesc(national_number_pattern='9[1-9]\\d{6}', possible_number_pattern='\\d{8}', example_number='94231234'),
    toll_free=PhoneNumberDesc(national_number_pattern='80[05]\\d{4}', possible_number_pattern='\\d{7}', example_number='8001234'),
    premium_rate=PhoneNumberDesc(national_number_pattern='90[0-8]\\d{4}', possible_number_pattern='\\d{7}', example_number='9001234'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    preferred_international_prefix='00',
    national_prefix='0',
    preferred_extn_prefix=' int. ',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{4})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[24]']),
        NumberFormat(pattern='(\\d{2})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['9[1-9]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d{3})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[89]0'], national_prefix_formatting_rule='0\\1')])
