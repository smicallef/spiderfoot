"""Auto-generated file, do not edit by hand. SX metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SX = PhoneMetadata(id='SX', country_code=1, international_prefix='011',
    general_desc=PhoneNumberDesc(national_number_pattern='[5789]\\d{9}', possible_number_pattern='\\d{7}(?:\\d{3})?'),
    fixed_line=PhoneNumberDesc(national_number_pattern='7215(?:4[2-8]|8[239]|9[056])\\d{4}', possible_number_pattern='\\d{7}(?:\\d{3})?', example_number='7215425678'),
    mobile=PhoneNumberDesc(national_number_pattern='7215(?:1[02]|2\\d|5[034679]|8[014-8])\\d{4}', possible_number_pattern='\\d{10}', example_number='7215205678'),
    toll_free=PhoneNumberDesc(national_number_pattern='8(?:00|44|55|66|77|88)[2-9]\\d{6}', possible_number_pattern='\\d{10}', example_number='8002123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='900[2-9]\\d{6}', possible_number_pattern='\\d{10}', example_number='9002123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='5(?:00|33|44|66|77|88)[2-9]\\d{6}', possible_number_pattern='\\d{10}', example_number='5002345678'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='1',
    national_prefix_for_parsing='1',
    leading_digits='721')
