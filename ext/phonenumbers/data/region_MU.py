"""Auto-generated file, do not edit by hand. MU metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_MU = PhoneMetadata(id='MU', country_code=230, international_prefix='0(?:0|[2-7]0|33)',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-9]\\d{6,7}', possible_number_pattern='\\d{7,8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:2(?:[03478]\\d|1[0-7]|6[1-69])|4(?:[013568]\\d|2[4-7])|5(?:44\\d|471)|6\\d{2}|8(?:14|3[129]))\\d{4}', possible_number_pattern='\\d{7,8}', example_number='2012345'),
    mobile=PhoneNumberDesc(national_number_pattern='5(?:2[59]\\d|4(?:2[1-389]|4\\d|7[1-9]|9\\d)|7\\d{2}|8(?:[0-2568]\\d|7[15-8])|9[0-8]\\d)\\d{4}', possible_number_pattern='\\d{8}', example_number='52512345'),
    toll_free=PhoneNumberDesc(national_number_pattern='80[012]\\d{4}', possible_number_pattern='\\d{7}', example_number='8001234'),
    premium_rate=PhoneNumberDesc(national_number_pattern='30\\d{5}', possible_number_pattern='\\d{7}', example_number='3012345'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='3(?:20|9\\d)\\d{4}', possible_number_pattern='\\d{7}', example_number='3201234'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    preferred_international_prefix='020',
    number_format=[NumberFormat(pattern='([2-46-9]\\d{2})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[2-46-9]']),
        NumberFormat(pattern='(5\\d{3})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['5'])])
