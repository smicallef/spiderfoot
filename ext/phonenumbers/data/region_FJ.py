"""Auto-generated file, do not edit by hand. FJ metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_FJ = PhoneMetadata(id='FJ', country_code=679, international_prefix='0(?:0|52)',
    general_desc=PhoneNumberDesc(national_number_pattern='[36-9]\\d{6}|0\\d{10}', possible_number_pattern='\\d{7}(?:\\d{4})?'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:3[0-5]|6[25-7]|8[58])\\d{5}', possible_number_pattern='\\d{7}', example_number='3212345'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:7[0-8]|8[034679]|9\\d)\\d{5}', possible_number_pattern='\\d{7}', example_number='7012345'),
    toll_free=PhoneNumberDesc(national_number_pattern='0800\\d{7}', possible_number_pattern='\\d{11}', example_number='08001234567'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    preferred_international_prefix='00',
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{4})', format='\\1 \\2', leading_digits_pattern=['[36-9]']),
        NumberFormat(pattern='(\\d{4})(\\d{3})(\\d{4})', format='\\1 \\2 \\3', leading_digits_pattern=['0'])],
    leading_zero_possible=True)
