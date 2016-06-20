"""Auto-generated file, do not edit by hand. TZ metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_TZ = PhoneMetadata(id='TZ', country_code=255, international_prefix='00[056]',
    general_desc=PhoneNumberDesc(national_number_pattern='\\d{9}', possible_number_pattern='\\d{7,9}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2[2-8]\\d{7}', possible_number_pattern='\\d{7,9}', example_number='222345678'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:6[125-9]|7[1-9])\\d{7}', possible_number_pattern='\\d{9}', example_number='621234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='80[08]\\d{6}', possible_number_pattern='\\d{9}', example_number='800123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='90\\d{7}', possible_number_pattern='\\d{9}', example_number='900123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='8(?:40|6[01])\\d{6}', possible_number_pattern='\\d{9}', example_number='840123456'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='41\\d{7}', possible_number_pattern='\\d{9}', example_number='412345678'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='([24]\\d)(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['[24]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='([67]\\d{2})(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['[67]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='([89]\\d{2})(\\d{2})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['[89]'], national_prefix_formatting_rule='0\\1')])
