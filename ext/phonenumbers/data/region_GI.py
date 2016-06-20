"""Auto-generated file, do not edit by hand. GI metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_GI = PhoneMetadata(id='GI', country_code=350, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2568]\\d{7}', possible_number_pattern='\\d{8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2(?:00\\d|1(?:6[24-7]|9\\d)|2(?:00|2[2457]))\\d{4}', possible_number_pattern='\\d{8}', example_number='20012345'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:5[46-8]|62)\\d{6}', possible_number_pattern='\\d{8}', example_number='57123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='80\\d{6}', possible_number_pattern='\\d{8}', example_number='80123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='8[1-689]\\d{6}', possible_number_pattern='\\d{8}', example_number='88123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='87\\d{6}', possible_number_pattern='\\d{8}', example_number='87123456'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{5})', format='\\1 \\2', leading_digits_pattern=['2'])])
