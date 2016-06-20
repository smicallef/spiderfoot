"""Auto-generated file, do not edit by hand. DO metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_DO = PhoneMetadata(id='DO', country_code=1, international_prefix='011',
    general_desc=PhoneNumberDesc(national_number_pattern='[589]\\d{9}', possible_number_pattern='\\d{7}(?:\\d{3})?'),
    fixed_line=PhoneNumberDesc(national_number_pattern='8(?:[04]9[2-9]\\d{6}|29(?:2(?:[0-59]\\d|6[04-9]|7[0-27]|8[0237-9])|3(?:[0-35-9]\\d|4[7-9])|[45]\\d{2}|6(?:[0-27-9]\\d|[3-5][1-9]|6[0135-8])|7(?:0[013-9]|[1-37]\\d|4[1-35689]|5[1-4689]|6[1-57-9]|8[1-79]|9[1-8])|8(?:0[146-9]|1[0-48]|[248]\\d|3[1-79]|5[01589]|6[013-68]|7[124-8]|9[0-8])|9(?:[0-24]\\d|3[02-46-9]|5[0-79]|60|7[0169]|8[57-9]|9[02-9]))\\d{4})', possible_number_pattern='\\d{7}(?:\\d{3})?', example_number='8092345678'),
    mobile=PhoneNumberDesc(national_number_pattern='8[024]9[2-9]\\d{6}', possible_number_pattern='\\d{7}(?:\\d{3})?', example_number='8092345678'),
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
    leading_digits='8[024]9',
    mobile_number_portable_region=True)
