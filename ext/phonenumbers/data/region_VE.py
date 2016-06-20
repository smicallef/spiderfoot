"""Auto-generated file, do not edit by hand. VE metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_VE = PhoneMetadata(id='VE', country_code=58, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[24589]\\d{9}', possible_number_pattern='\\d{7,10}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:2(?:12|3[457-9]|[58][1-9]|[467]\\d|9[1-6])|50[01])\\d{7}', possible_number_pattern='\\d{7,10}', example_number='2121234567'),
    mobile=PhoneNumberDesc(national_number_pattern='4(?:1[24-8]|2[46])\\d{7}', possible_number_pattern='\\d{10}', example_number='4121234567'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{7}', possible_number_pattern='\\d{10}', example_number='8001234567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='900\\d{7}', possible_number_pattern='\\d{10}', example_number='9001234567'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{7})', format='\\1-\\2', national_prefix_formatting_rule='0\\1', domestic_carrier_code_formatting_rule='$CC \\1')])
