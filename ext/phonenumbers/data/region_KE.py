"""Auto-generated file, do not edit by hand. KE metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_KE = PhoneMetadata(id='KE', country_code=254, international_prefix='000',
    general_desc=PhoneNumberDesc(national_number_pattern='20\\d{6,7}|[4-9]\\d{6,9}', possible_number_pattern='\\d{7,10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='20\\d{6,7}|4(?:[0136]\\d{7}|[245]\\d{5,7})|5(?:[08]\\d{7}|[1-79]\\d{5,7})|6(?:[01457-9]\\d{5,7}|[26]\\d{7})', possible_number_pattern='\\d{7,9}', example_number='202012345'),
    mobile=PhoneNumberDesc(national_number_pattern='7(?:[0-36]\\d|5[0-6]|[79][0-7]|8[0-25-9])\\d{6}', possible_number_pattern='\\d{9}', example_number='712123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='800[24-8]\\d{5,6}', possible_number_pattern='\\d{9,10}', example_number='800223456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='900[02-9]\\d{5}', possible_number_pattern='\\d{9}', example_number='900223456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='005|0',
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{5,7})', format='\\1 \\2', leading_digits_pattern=['[24-6]'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d{3})(\\d{6})', format='\\1 \\2', leading_digits_pattern=['7'], national_prefix_formatting_rule='0\\1'),
        NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{3,4})', format='\\1 \\2 \\3', leading_digits_pattern=['[89]'], national_prefix_formatting_rule='0\\1')],
    mobile_number_portable_region=True)
