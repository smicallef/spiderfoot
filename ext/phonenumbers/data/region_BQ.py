"""Auto-generated file, do not edit by hand. BQ metadata"""
from ..phonemetadata import NumberFormat, PhoneNumberDesc, PhoneMetadata

PHONE_METADATA_BQ = PhoneMetadata(id='BQ', country_code=599, international_prefix='00',
    general_desc=PhoneNumberDesc(national_number_pattern='[347]\\d{6}', possible_number_pattern='\\d{7}'),
    fixed_line=PhoneNumberDesc(national_number_pattern='(?:318[023]|416[023]|7(?:1[578]|50)\\d)\\d{3}', possible_number_pattern='\\d{7}', example_number='7151234'),
    mobile=PhoneNumberDesc(national_number_pattern='(?:318[14-68]|416[15-9]|7(?:0[01]|7[07]|[89]\\d)\\d)\\d{3}', possible_number_pattern='\\d{7}', example_number='3181234'),
    toll_free=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    premium_rate=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    shared_cost=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    personal_number=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voip=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    pager=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    uan=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    voicemail=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'),
    no_international_dialling=PhoneNumberDesc(national_number_pattern='NA', possible_number_pattern='NA'))
