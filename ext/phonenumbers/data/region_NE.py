"""Auto-generated file, do not edit by hand. NE metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_NE = PhoneMetadata(id='NE', country_code=227, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[0289]\\d{7}', possible_number_pattern='\\d{8}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='2(?:0(?:20|3[1-7]|4[134]|5[14]|6[14578]|7[1-578])|1(?:4[145]|5[14]|6[14-68]|7[169]|88))\\d{4}', possible_number_pattern='\\d{8}', example_number='20201234'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:8[089]|9\\d)\\d{6}', possible_number_pattern='\\d{8}', example_number='93123456'),
    toll_free=PhoneNumberDesc(national_number_pattern='08\\d{6}', possible_number_pattern='\\d{8}', example_number='08123456'),
    premium_rate=PhoneNumberDesc(national_number_pattern='09\\d{6}', possible_number_pattern='\\d{8}', example_number='09123456'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{2})(\\d{2})(\\d{2})(\\d{2})', format='\\1 \\2 \\3 \\4', leading_digits_pattern=['[289]|09']),
        NumberFormat(pattern='(08)(\\d{3})(\\d{3})', format='\\1 \\2 \\3', leading_digits_pattern=['08'])],
    leading_zero_possible=True)
