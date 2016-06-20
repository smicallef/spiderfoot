"""Auto-generated file, do not edit by hand. SB metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_SB = PhoneMetadata(id='SB', country_code=677, international_prefix='0[01]',
    general_desc=PhoneNumberDesc(national_number_pattern='[1-9]\\d{4,6}', possible_number_pattern='\\d{5,7}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:1[4-79]|[23]\\d|4[0-2]|5[03]|6[0-37])\\d{3}', possible_number_pattern='\\d{5}', example_number='40123'),
    mobile=PhoneNumberDesc(national_number_pattern='48\\d{3}|7(?:30|[46-8]\\d|5[025-9]|9[0-5])\\d{4}|8[4-9]\\d{5}|9(?:1[2-9]|2[013-9]|3[0-2]|[46]\\d|5[0-46-9]|7[0-689]|8[0-79]|9[0-8])\\d{4}', possible_number_pattern='\\d{5,7}', example_number='7421234'),
    toll_free=PhoneNumberDesc(national_number_pattern='1[38]\\d{3}', possible_number_pattern='\\d{5}', example_number='18123'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='5[12]\\d{3}', possible_number_pattern='\\d{5}', example_number='51123'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{5})', format='\\1 \\2', leading_digits_pattern=['[7-9]'])])
