"""Auto-generated file, do not edit by hand. SG metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SG = PhoneMetadata(id='SG', country_code=65, international_prefix='0[0-3]\\d',
    general_desc=PhoneNumberDesc(national_number_pattern='[36]\\d{7}|[17-9]\\d{7,10}', possible_number_pattern='\\d{8,11}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='6[1-9]\\d{6}', possible_number_pattern='\\d{8}', example_number='61234567'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:8[1-8]|9[0-8])\\d{6}', possible_number_pattern='\\d{8}', example_number='81234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='1?800\\d{7}', possible_number_pattern='\\d{10,11}', example_number='18001234567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='1900\\d{7}', possible_number_pattern='\\d{11}', example_number='19001234567'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='3[12]\\d{6}', possible_number_pattern='\\d{8}', example_number='31234567'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='7000\\d{7}', possible_number_pattern='\\d{11}', example_number='70001234567'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='([3689]\\d{3})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[369]|8[1-9]']),
        NumberFormat(pattern='(1[89]00)(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['1[89]']),
        NumberFormat(pattern='(7000)(\\d{4})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['70']),
        NumberFormat(pattern='(800)(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['80'])],
    mobile_number_portable_region=True)
