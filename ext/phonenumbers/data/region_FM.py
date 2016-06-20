"""Auto-generated file, do not edit by hand. FM metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_FM = PhoneMetadata(id='FM', country_code=691, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[39]\\d{6}', possible_number_pattern='\\d{7}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='3[2357]0[1-9]\\d{3}|9[2-6]\\d{5}', possible_number_pattern='\\d{7}', example_number='3201234'),
    mobile=PhoneNumberDesc(national_number_pattern='3[2357]0[1-9]\\d{3}|9[2-7]\\d{5}', possible_number_pattern='\\d{7}', example_number='3501234'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    number_format=[NumberFormat(pattern='(\\d{3})(\\d{4})', format='\\1 \\2')])
