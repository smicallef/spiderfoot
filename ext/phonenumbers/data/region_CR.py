"""Auto-generated file, do not edit by hand. CR metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_CR = PhoneMetadata(id='CR', country_code=506, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[24-9]\\d{7,9}', possible_number_pattern='\\d{8,10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2[0-24-7]\\d{6}', possible_number_pattern='\\d{8}', example_number='22123456'),
    mobile=PhoneNumberDesc(national_number_pattern='5(?:0[01]|7[0-3])\\d{5}|(?:[67][0-3]|8[3-9])\\d{6}', possible_number_pattern='\\d{8}', example_number='83123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{7}', possible_number_pattern='\\d{10}', example_number='8001234567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='90[059]\\d{7}', possible_number_pattern='\\d{10}', example_number='9001234567'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='210[0-6]\\d{4}|4\\d{7}|5100\\d{4}', possible_number_pattern='\\d{8}', example_number='40001234'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix_for_parsing='(19(?:0[012468]|1[09]|20|66|77|99))',
    number_format=[NumberFormat(pattern='(\\d{4})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[24-7]|8[3-9]'], domestic_carrier_code_formatting_rule='$CC \\1'),
        NumberFormat(pattern='(\\d{3})(\\d{3})(\\d{4})', format='\\1-\\2-\\3', leading_digits_pattern=['[89]0'], domestic_carrier_code_formatting_rule='$CC \\1')])
