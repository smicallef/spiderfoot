"""Auto-generated file, do not edit by hand. SL metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SL = PhoneMetadata(id='SL', country_code=232, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-9]\\d{7}', possible_number_pattern='\\d{6,8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='[235]2[2-4][2-9]\\d{4}', possible_number_pattern='\\d{6,8}', example_number='22221234'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:2[15]|3[03-5]|4[04]|5[05]|66|7[6-9]|88|99)\\d{6}', possible_number_pattern='\\d{6,8}', example_number='25123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    national_prefix='0',
    national_prefix_for_parsing='0',
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{6})', format='\\1 \\2', national_prefix_formatting_rule='(0\\1)')])
