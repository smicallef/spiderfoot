"""Auto-generated file, do not edit by hand. WS metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_WS = PhoneMetadata(id='WS', country_code=685, international_prefix='0',
    general_desc=PhoneNumberDesc(national_number_pattern='[2-8]\\d{4,6}', possible_number_pattern='\\d{5,7}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:[2-5]\\d|6[1-9]|84\\d{2})\\d{3}', possible_number_pattern='\\d{5,7}', example_number='22123'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:60|7[25-7]\\d)\\d{4}', possible_number_pattern='\\d{6,7}', example_number='601234'),
    toll_free=PhoneNumberDesc(national_number_pattern='800\\d{3}', possible_number_pattern='\\d{6}', example_number='800123'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(8\\d{2})(\\d{3,4})', format='\\1 \\2', leading_digits_pattern=['8']),
        NumberFormat(pattern='(7\\d)(\\d{5})', format='\\1 \\2', leading_digits_pattern=['7']),
        NumberFormat(pattern='(\\d{5})', format='\\1', leading_digits_pattern=['[2-6]'])])
